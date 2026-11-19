{
  "variables": {
    "masscan_src": "src/masscan/src",
    "shim": "<(module_root_dir)/src/shim/libmasscan-shim.h"
  },
  "target_defaults": {
    "xcode_settings": { "MACOSX_DEPLOYMENT_TARGET": "11.0" }
  },
  "targets": [
    {
      # Unmodified upstream masscan, with the shim force-included.
      "target_name": "masscan_core",
      "type": "static_library",
      "sources": [
        "<!@(node scripts/sources.js)",
        "src/masscan-output.c"
      ],
      "include_dirs": [ "<(masscan_src)" ],
      "cflags": [ "-fPIC", "-std=gnu99", "-O2", "-w", "-include", "<(shim)" ],
      "xcode_settings": {
        "OTHER_CFLAGS": [ "-std=gnu99", "-O2", "-w", "-include", "<(shim)" ],
        "GCC_WARN_INHIBIT_ALL_WARNINGS": "YES"
      }
    },
    {
      "target_name": "masscan",
      "dependencies": [ "masscan_core" ],
      "sources": [ "src/addon.c", "src/hooks.c", "src/runner.c" ],
      "include_dirs": [ "src", "<(masscan_src)" ],
      "cflags": [ "-std=gnu99", "-O2" ],
      "xcode_settings": {
        "OTHER_CFLAGS": [ "-std=gnu99", "-O2" ]
      },
      "conditions": [
        [ "OS=='linux'", {
          "libraries": [ "-lm", "-ldl", "-lrt", "-lpthread" ]
        }],
        [ "OS=='mac'", {
          "libraries": [ "-lm" ]
        }]
      ]
    }
  ]
}
