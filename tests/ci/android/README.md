# Android CI for AWS-LC
AWS-LC wants to ensure that our tests and build work correctly on Android. Insipred from the CRT Team's [`AWSCRTAndroidTestRunner`](https://github.com/awslabs/aws-c-common/tree/main/AWSCRTAndroidTestRunner), this mini Android test harness is intended to be used within our Android CI with AWS Device Farm. The tests will include `crypto_test`, `urandom_test`, `decrepit_test` and `ssl_test`, referenced from regular test dimensions. This app can be tested with the docker image at `tests/ci/docker_images/linux-x86/ubuntu-20.04_android`.

## `AWSLCAndroidTestRunner` Setup
The commands below help build the app within our Android CI's docker image. The docker image is only made to support cross-compiling AWS-LC with Android toolchains, building the `AWSLCAndroidTestRunner` apks, and uploading and kicking off the tests in AWS Device Farm. Running and testing on connected Android devices or emulators via `./gradlew cC` isn't configured within the docker image.
1. Assuming all the commands are being run from this folder: `cd tests/ci/android`
2. `docker build -t ubuntu-20.04:android ../docker_images/linux-x86/ubuntu-20.04_android/`
3. Run the docker image from root of aws-lc. The container needs access to aws-lc's source code to build.
   ```
   docker run -it -v `pwd`:`pwd` -w `pwd` ubuntu-20.04:android`
   cd ../../../
   docker run -it -v `pwd`:`pwd` -w `pwd` ubuntu-20.04:android
   ```
4. `cd tests/ci/android/AWSLCAndroidTestRunner`
5. Run `./gradlew assembleDebug assembleAndroidTest` to build both the app and test apks with the AWS-LC non-FIPS debug build.
6. Run `./gradlew assembleDebug assembleAndroidTest -PRelease` to build both the app and test apks with the AWS-LC non-FIPS release build.
7. Run `./gradlew assembleDebug assembleAndroidTest -PFIPS` to build both the app and test apks with the AWS-LC FIPS build (only armv8 is supported).

## Local testing
Alternatively run `./gradlew cC` to build both apks, then run the tests locally on a connected Android device/emulator right after. Add the `-PRelease` or `-PFIPS` as needed.\
Emulators are not easily configurable out of the box on Linux, and it would be better to run `./gradlew cC` on a connected Android phone or an emulator running on MacOS. It's also worth noting that accessing your connected Android phone from a docker container will require extra `adb` permission configurations. You could consider using the docker image to build the apks, `chown` on the build output files, and then running `./gradlew cC` to upload the apks on to your external device/emulator.

### Emulator
1. To set up an emulator on Mac OS X, go to https://developer.android.com/studio and download the latest version for Android Studio. Launch and install the dmg file, and the set up wizard should guide you through the setup. Once installed, you get the Welcome to Android Studio window, where you can configure and use SDK manager to install Android SDKs and dependencies.
2. Android emulators are managed through a UI called AVD Manager, which can be accessed from Android Studio. Start the Android Studio app, then create a blank project.
3. Go to the Tools menu -> Android -> AVD Manager. If no emulator has been created you should click the "Create Virtual Device" button.
4. Select "Pixel 2" (or any of the newer preferred options), then select "x86" images and download R (API Level:30, ABI:x86_64, Android 11.0 (Google APIs)). Click through the rest of the virtual device set up and then "Finish". The newly created device should be launchable from the AVD Manager window.
5. Run `./gradlew cC` on `AWSLCAndroidTestRunner`, and the emulator will be automatically detected. Outputted debug logs from the emulator device can be seen from the log interface in any blank project created in Android Studio. You can also use `awslc-test` tag to filter through specific logs outputted from running `AWSLCAndroidTestRunner`.

## Updating the Android CI
Although the Android CI's codebuild resources are integrated with our current CI infrastructure, it also relies on additional Device Farm resources to run the real device tests after cross-compiling within Codebuild. To update the cdk/docker images for Android, refer to `tests/ci/cdk/README.md`. The cdk action type would be `update-android-ci`. To configure the device farm resources needed, steps on how to do so are provided below.

## Setup Device Farm CI Resources
1. We'll be using `aws cli` to retrieve the ARNs of our Device Farm project and Device Pools. Paste account's Isengard credentials inside a terminal to sign in. 
2. Run `aws devicefarm create-project --name ${project_name}` Save the arn ouputted after running the command as `${project_arn}`. Our current project name is `aws-lc-android-ci`.
3. Our FIPS device farm CI is set up to run on two random Android devices with at least Android 11. Run the following command to create the FIPS Device Pool: 
```
aws devicefarm create-device-pool --project-arn ${project_arn} --name "aws-lc-device-pool-fips" --description "AWS-LC FIPS Device Pool" --rules file://devicepool_rules_fips.json --max-devices 2
```
4. Our non-FIPS device farm CI is set up to run on two random Android devices with at least Android 10. Run the following command to create the non-FIPS Device Pool: 
```
aws devicefarm create-device-pool --project-arn ${project_arn} --name "aws-lc-device-pool" --description "AWS-LC Device Pool" --rules file://devicepool_rules.json --max-devices 2
```
5. Use the project arn and the corresponding device pool arns that wish to be tested upon, and run the `tests/ci/kickoff_devicefarm_job.sh` script with `--devicefarm-project-arn` and `--devicefarm-device-pool-arn` specified with the specified values. If we're updating our team account, change the `DEVICEFARM_PROJECT` and the `DEVICEFARM_DEVICE_POOL` variable to the new values.

## Known Issues
`AWSLCAndroidTestRunner` is built by building the `aws-lc` test executuables as shared objects to be ran inside the android app. This approach works for most cases, but devices that run OS versions of Android 10 have been known to fail with the FIPS version of `AWSLCAndroidTestRunner`. This is because Android 10 has an "Execute-only Memory (XOM) for AArch64 Binaries" restriction turned on in Android 10 kernels, which clashes with the `bcm.o` in FIPS trying to read test related files/memory during FIPS test executing. \
The provided way to get around this issue is to wrap memory segments in tests as read+execute by calling `mprotect()`, but this could be considered too much tedious work to support the Android 10 edge case when it's only an issue when trying to run test executables from our app. From Android's docs: "XOM is only supported in Android 10 and has been removed in Android 11 and kernel changes removing it have been backported to 4.9(Android common kernel), so the common kernel no longer supports XOM." Most of AWS Device Farm's Android 10 devices still have XOM on, which causes failures when we try to test against those devices.\
One day when all in the world is right and Github Actions/Codebuild supports a MacOSX M1 instance to test upon, we can consider accessing an `armv8` Android emulator via `adb` to run our Android tests. We would have more control over the system images and the support is already there with `util/run_android_tests.go`.

Resources: 
* https://source.android.com/devices/tech/debug/execute-only-memory#refactoring
* https://developer.android.com/about/versions/10/behavior-changes-all#xom-binaries
