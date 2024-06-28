# Welcome to ANON EU

This repository is a POC of anon EU, leveraging EU IDs signatures for proof of personhood with SNARKs.

It does not contain the front-end logic that authenticate and read the chip inside of the EU ID. To extract the Document Security Object (SOD) I used [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader).

For now the circuit is:

- Verifying the signature of the Document Signer (DS) certificate contained in the SOD with the Country Signing Certificate Authority (CSCA) public key. You can find the CSCA certificate in `assets/french.pem`;
- Extracting the DS signed public key from the signed certificate;
- Verifying that the ID was signed with the DS public key;
- Verify the hash chain starting from the mrz (Data Group 1) -> eContent that contains a concatenation of the Data Group hashes -> Signed Data;
