{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "argon2/argon2.c",
 				"argon2/best.c",
 				"argon2/blake2b.c",
 				"argon2/core.c",
 				"argon2/encoding.c",
 				"argon2/thread.c",
            ],
            "include_dirs": [
                "crypto",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_cc": [
                "-std=c++0x"
            ],
        }
    ]
}
