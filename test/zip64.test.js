"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const Constants = require("../util").Constants;

describe("zip64", () => {
    it("writes and reads archives with more than 65535 entries", function () {
        // building and reading back 65536 entries is slow on the older node
        // versions of the test matrix
        this.timeout(120000);

        const entryCount = 0x10000;
        const zip = new Zip({ noSort: true });

        for (let i = 0; i < entryCount; i++) {
            zip.addFile(`file-${i}.txt`, "");
        }

        const buffer = zip.toBuffer();

        // the zip64 end of central directory record and its locator have to
        // precede the classic end record
        const eocdOffset = buffer.length - Constants.ENDHDR;
        expect(buffer.readUInt32LE(eocdOffset)).to.equal(Constants.ENDSIG);
        expect(buffer.readUInt32LE(eocdOffset - Constants.END64HDR)).to.equal(Constants.END64SIG);
        expect(buffer.readUInt32LE(eocdOffset - Constants.END64HDR - Constants.ZIP64HDR)).to.equal(Constants.ZIP64SIG);
        // classic record keeps the placeholder values
        expect(buffer.readUInt16LE(eocdOffset + Constants.ENDTOT)).to.equal(Constants.EF_ZIP64_OR_16);

        const readZip = new Zip(buffer);

        expect(readZip.getEntries()).to.have.lengthOf(entryCount);
        expect(readZip.getEntries()[0].entryName).to.equal("file-0.txt");
    });

    it("keeps the zip file comment at the end of the archive", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from("content"));
        zip.addZipComment("adm-zip comment");

        const buffer = zip.toBuffer();

        expect(buffer.slice(buffer.length - "adm-zip comment".length).toString()).to.equal("adm-zip comment");
        expect(new Zip(buffer).getZipComment()).to.equal("adm-zip comment");
    });
});
