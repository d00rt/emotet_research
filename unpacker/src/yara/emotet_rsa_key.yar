rule EmotetRSAKey1
{
    meta:
        author       = "d00rt - @D00RT_RM"

        version      = "1.0.0"
        maintainer   = "d00rt - @D00RT_RM"
        email        = "d00rt.fake@gmail.com"
        status       = "Testing"

	strings:
		$rsa_key = {
			30 68 02 61 00 A5 AB 62 8D A5 4B E7 97 A5 0F 24
			B3 BA 95 D4 35 6D 60 17 F6 29 FC E9 EA ED 97 C1
			31 B3 B8 47 E2 20 8A DF 04 33 92 2D 44 31 DF 1F
			B0 84 DD 3D F3 8C 59 08 98 C3 BF 7B D1 46 04 15
			FF EF 50 9C 6E 08 88 E7 1C 10 30 0E B1 61 15 42
			68 AE 4A 0E 49 6D 4B 4A 42 00 36 6B 27 9D D0 A2
			85 BD FE BF 5B 02 03 01
		}
	condition:
		$rsa_key
}

rule EmotetRSAKey2
{
    meta:
        author       = "d00rt - @D00RT_RM"

        version      = "1.0.0"
        maintainer   = "d00rt - @D00RT_RM"
        email        = "d00rt.fake@gmail.com"
        status       = "Testing"

	strings:
		$rsa_key = {
			30 68 02 61 00 A2 CE B7 FD 7F C9 91 FC 55 58 F3
			C8 D0 11 5D C7 12 F6 38 70 9B 50 28 05 B5 6F 3D
			C1 5B CE 17 50 77 C0 59 1D 3F 55 C4 94 25 03 20
			1D 93 D8 05 A0 AA 2A AD 7A E3 F2 50 02 5E 36 47
			C0 D8 E1 FD D1 CE 6F A9 93 55 8C 5A 61 7B 55 DB
			09 97 DF 68 43 AD 0A A5 B0 F6 8B B7 71 BE FE 42
			B9 EB 41 C6 5B 02 03 01
		}
	condition:
		$rsa_key
}

rule EmotetRSAKey3
{
    meta:
        author       = "d00rt - @D00RT_RM"

        version      = "1.0.0"
        maintainer   = "d00rt - @D00RT_RM"
        email        = "d00rt.fake@gmail.com"
        status       = "Testing"

	strings:
		$rsa_key = {
			30 68 02 61 00 BC E6 5F DB 9F E4 BE 71 0F F8 94
			FB A4 43 73 D6 C2 C3 6D 67 33 AA 25 02 51 35 DA
			0D FA C4 D0 C7 C7 1D F3 A8 F5 58 3F CA F1 97 DC
			BA F5 B4 4D 49 AF 9B 75 35 DE 52 D0 ED 9B 32 1A
			5D 5D A6 90 5E 3D 24 A5 F3 F3 EF 75 A2 1B 6C 2F
			F1 FE C2 7C 9A 9F FB 43 52 22 C1 1B A8 8E 11 D3
			E3 22 5A A7 6F 02 03 01
		}
	condition:
		$rsa_key
}

rule EmotetRSAKey4
{
    meta:
        author       = "d00rt - @D00RT_RM"

        version      = "1.0.0"
        maintainer   = "d00rt - @D00RT_RM"
        email        = "d00rt.fake@gmail.com"
        status       = "Testing"

	strings:
		$rsa_key = {
			30 68 02 61 00 B3 80 57 F7 D2 29 E9 78 3E 22 60
			18 A7 72 79 09 D0 AB FA 12 1A EB FB 6F 0F FD 3F
			4D 1F D5 4D F4 87 55 A0 AB 2C C8 53 33 53 30 B5
			DD 63 E9 43 53 19 1C 30 49 D7 CA A1 F0 90 A3 C9
			58 B1 28 84 3F E2 C3 0B F4 65 F2 B6 DE 59 A9 3A
			B1 79 56 2E CB 49 49 B0 2C 3A EE 16 2F 42 A6 60
			9D 2A 21 58 FB 02 03 01 00 01
		}
	condition:
		$rsa_key
}

rule EmotetRSAKeyOldVersion1
{
    meta:
        author       = "d00rt - @D00RT_RM"

        version      = "1.0.0"
        maintainer   = "d00rt - @D00RT_RM"
        email        = "d00rt.fake@gmail.com"
        status       = "Testing"

	strings:
		$rsa_key = {
			30 68 02 61 00 AE 26 2B 2D 54 40 57 4E 52 4C C4
			50 2C CE 70 F0 69 9B 6E A5 0D D4 10 80 C1 D0 BC
			E2 B7 38 84 C1 47 0C DE 80 07 CE A1 12 FB AD 98
			FC B9 7E 2C 5D C8 EF B1 57 82 CD 00 2E E6 0E 4B
			8E A1 98 C3 8C 4F 08 95 FE 96 5C 47 AE 72 A8 CD
			FE 89 1C 5A 1A 96 29 83 CE 36 D5 D5 E0 55 D3 14
			58 70 42 81 EB 02 03 01 00 01
		}
	condition:
		$rsa_key
}