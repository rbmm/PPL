# PPL
 run process as PPL Antimalware

machine must be in into testsigning mode ( bcdedit /set testsigning on )

ELAM Driver ( x64\ELAM.dll ) signed with "ELAM Test.cer"


```
EKU:
	Early Launch Antimalware Driver (1.3.6.1.4.1.311.61.4.1)
	Code Signing (1.3.6.1.5.5.7.3.3)

```

PPL.exe signed with "PPL Test.cer"


```
EKU:
	Protected Process Light Verification (1.3.6.1.4.1.311.10.3.22)
	Windows System Component Verification (1.3.6.1.4.1.311.10.3.6)
	Code Signing (1.3.6.1.5.5.7.3.3)

```


ELAM.dll containing sha256 hash of "PPL Test.cer"

```
			DATA_BLOB db; // here "PPL Test.cer"
			UCHAR hash[0x20];
			PCERT_SIGNED_CONTENT_INFO TBSData;
			if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT, db.pbData, db.cbData, 
				CRYPT_DECODE_ALLOC_FLAG|
				CRYPT_DECODE_NOCOPY_FLAG|
				CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &TBSData, &cb))
			{
				CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, 
					TBSData->ToBeSigned.pbData, 
					TBSData->ToBeSigned.cbData, h, &(cb = sizeof(hash)));

				DumpBytes(hash, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);

				LocalFree(TBSData);
			}

MICROSOFTELAMCERTIFICATEINFO MSELAMCERTINFOID
{
      1,
      L"a3d01b57cb6c1b3db8832851b322b5c00bd4849613f369de7f7ebe929c90e85e\0",
      0x800C,
      L"\0"
}

```

or certutil -dump "PPL Test.cer" and use "Signature Hash"


ELAM.dll must be in same folder as PPL.exe

