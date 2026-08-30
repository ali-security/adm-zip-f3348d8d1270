"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a multi-gigabyte size and
// force a matching Buffer.alloc, OOM-killing the process. The allocation must be
// bound by the data actually present in the archive, not by the declared size.

const MB = 1024 * 1024;
// 1.5 GB: far above any plausible allocation for the payloads below, while still
// under Buffer's maximum length on every node version this package supports.
const DECLARED = 1536 * MB;
// No single allocation made while reading these archives may come near this.
const ALLOC_LIMIT = 64 * MB;
const RSS_LIMIT_MB = 256;

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. `crc` defaults to a deliberately
// wrong value, since the allocation used to happen before the crc check.
function craftBomb(declaredSize, method, content, crc) {
    const name = Buffer.from("a.txt");
    const checksum = crc >>> 0;
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(checksum),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(checksum),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Records the largest Buffer.alloc request made while `fn` runs. This is the
// deterministic half of the assertion: the vulnerable code asked for the
// declared size up front, the fixed code never does.
function largestAllocation(fn) {
    const original = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (typeof size === "number" && size > largest) largest = size;
        return original.apply(Buffer, arguments);
    };
    try {
        fn();
    } finally {
        Buffer.alloc = original;
    }
    return largest;
}

describe("zip decompression bomb (declared size) - CVE-2026-39244", () => {
    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"), 0));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        const largest = largestAllocation(() => {
            expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        });
        // "within" and not "below": the entry output buffer IS allocated here, so a
        // largest of 0 would mean the hook above missed it and the bound is vacuous
        expect(largest, "allocation must be bound by real data, not declared size").to.be.within(1, ALLOC_LIMIT);
        const grewMB = (process.memoryUsage().rss - before) / MB;
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(RSS_LIMIT_MB);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00]), 0));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        const largest = largestAllocation(() => {
            expect(() => zip.getEntries()[0].getData()).to.throw();
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
        const grewMB = (process.memoryUsage().rss - before) / MB;
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(RSS_LIMIT_MB);
    });

    it("does not allocate the declared size through the high level read APIs", () => {
        // every documented read path funnels through the same entry decompression
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"), 0));
        const largest = largestAllocation(() => {
            expect(zip.test()).to.equal(false);
            expect(() => zip.readAsText("a.txt")).to.throw(/CRC32/);
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.within(1, ALLOC_LIMIT);
    });

    it("does not allocate the declared size for a DEFLATED entry that decompresses correctly", () => {
        // Valid deflate stream and valid crc, only the declared size lies. The
        // entry still has to read back correctly, from a bounded allocation.
        const payload = Buffer.from("adm-zip");
        const zip = new Zip(craftBomb(DECLARED, 8, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        let data = null;
        const largest = largestAllocation(() => {
            data = zip.readFile("a.txt");
        });
        expect(data.equals(payload)).to.equal(true);
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
    });

    it("does not allocate the declared size when reading asynchronously", (done) => {
        const payload = Buffer.from("adm-zip async");
        const zip = new Zip(craftBomb(DECLARED, 8, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        const original = Buffer.alloc;
        let largest = 0;
        Buffer.alloc = function (size) {
            if (typeof size === "number" && size > largest) largest = size;
            return original.apply(Buffer, arguments);
        };
        zip.readFileAsync("a.txt", (data, err) => {
            Buffer.alloc = original;
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
                done();
            } catch (assertion) {
                done(assertion);
            }
        });
    });

    it("still reads a legitimate STORED entry", () => {
        const payload = Buffer.from([1, 2, 3, 4, 5]);
        const zip = new Zip(craftBomb(payload.length, 0 /* STORED */, payload, Utils.crc32(payload)));
        expect([...zip.readFile("a.txt")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});
