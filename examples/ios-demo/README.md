# iOS evaluation app

This is a real UIKit/Objective-C app compiled for arm64 iOS. It is provided as
an inspectable static-analysis target, with source-known answers. Building and
analyzing it does not launch the app or send any requests.

From the repository root, with Xcode and an iPhoneOS SDK installed:

```sh
python3 examples/build_ios_demo.py
python3 examples/build_ios_demo.py --stripped
```

Outputs are `.aire/demo/AireDemo.ipa` and
`.aire/demo/AireDemo-stripped.ipa`. Their generated `*-build/Payload` directories
retain the actual Mach-O executables for independent analysis. The IPAs are
unsigned and do not include a provisioning profile. The builder prints its
compiler command and the selected SDK path. It does not install dependencies.

The fixture includes:

- `FavoriteStore`: `NSUserDefaults` persistence, empty-input rejection,
  duplicate detection, and restoration under the key `aire.favorites.v1`.
- `LoginService`: an `NSURLSession` JSON POST, completion-block handling, and
  an error logging path. The `.invalid` URL has no production service.
- `PreviewStore`: a separate `saveFavorite:` implementation which only copies
  an instance variable and logs it. This makes selector ambiguity testable.
- `DemoViewController`: localized buttons with target/action registration and
  calls into the three feature classes.

The standard build retains method symbols. The stripped build removes local
and debug symbols; Objective-C runtime metadata and selector strings still
exist. Current Apple toolchains may encode pointers through chained fixups,
which requires a capable analysis backend for complete metadata recovery.

[`../benchmark.json`](../benchmark.json) contains six questions and source
anchors. `evaluation_status: not_run` and `agent_result: null` mean that expected
answers have not been scored against an Agent run. They must not be reported as
a measured success rate.

An opt-in test compiles and inventories the genuine fixture:

```sh
AIRE_TEST_XCODE=1 python -m pytest tests/test_demo.py -q
```
