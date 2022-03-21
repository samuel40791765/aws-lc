# Android CI for AWS-LC
AWS-LC wants to ensure that our tests and build work correctly on Android. Insipred from the CRT Team's [`AWSCRTAndroidTestRunner`](https://github.com/awslabs/aws-c-common/tree/main/AWSCRTAndroidTestRunner), this mini Android test harness is intended to be used within our Android CI with AWS Device Farm. The tests will include `crypto_test`, `urandom_test`, `decrepit_test` and `ssl_test`, referenced from regular test dimensions. This app can be tested with the docker image at `tests/ci/docker_images/linux-x86/ubuntu-20.04_android`.

## `AWSLCAndroidTestRunner` Setup
1. Assuming all the commands are being run from this folder: `cd tests/ci/android`
2. `docker build -t ubuntu-20.04:android ../docker_images/linux-x86/ubuntu-20.04_android/`
3. Run the docker image from root of aws-lc. The container needs access to aws-lc's source code to build.
   ```
   docker run -it -v `pwd`:`pwd` -w `pwd` ubuntu-20.04:android`
   ```
4. `cd AWSLCAndroidTestRunner`
5. Run `./gradlew assembleDebug assembleAndroidTest` to build both the app and test apks with the AWS-LC non-FIPS debug build.
6. Run `./gradlew assembleDebug assembleAndroidTest -PRelease` to build both the app and test apks with the AWS-LC non-FIPS release build.
7. Run `./gradlew assembleDebug assembleAndroidTest -PFIPS` to build both the app and test apks with the AWS-LC FIPS build (only armv8 is supported).

## Local testing
Alternatively run `./gradlew cC` to build both apks, then run the tests locally on a connected Android device/emulator right after. Add the `-PRelease` or `-PFIPS` as needed.

### Emulator
1. To set up an emulator on Mac OS X, go to https://developer.android.com/studio and download the latest version for Android Studio. Launch and install the dmg file, and the set up wizard should guide you through the setup. Once installed, you get the Welcome to Android Studio window, where you can configure and use SDK manager to install Android SDKs and dependencies.
2. Android emulators are managed through a UI called AVD Manager, which can be accessed from Android Studio. Start the Android Studio app, then create a blank project.
3. Go to the Tools menu -> Android -> AVD Manager. If no emulator has been created you should click the "Create Virtual Device" button.
4. Select "Pixel 2" (or any of the newer preferred options), then select "x86" images and download R (API Level:30, ABI:x86_64, Android 11.0 (Google APIs)). Click through the rest of the virtual device set up and then "Finish". The newly created device should be launchable from the AVD Manager window.
5. Run `./gradlew cC` on `AWSLCAndroidTestRunner`, and the emulator will be automatically detected. Outputted debug logs from the emulator device can be seen from the log interface in any blank project created in Android Studio. You can also use `awslc-test` tag to filter through specific logs outputted from running `AWSLCAndroidTestRunner`.

## Updating the Android CI
Although the Android CI's codebuild resources are integrated with our current CI infrastructure, it also relies on additional Device Farm resources to run the real device tests after cross-compiling within Codebuild. To update the cdk/docker images for Android, refer to `aws-lc/tests/ci/cdk/README.md`. The cdk action type would be `update-android-ci`. To configure the device farm resources needed, steps on how to do so are provided below.

## Setup Device Farm CI Resources
1. Sign in to our team's account and access the Device Farm console at https://console.aws.amazon.com/devicefarm.
2. On the Device Farm navigation panel, choose Mobile Device Testing, then choose Projects.
3. Choose New project.
4. Enter a name for your project, then choose Submit. Our current project name is `aws-lc-android-ci`. No specific settings need to be specified. 
5. Go to the settings of the device farm project you just created and click into the `Device pools` tab. From there, you can create device pools specifying conditions and devices that you wish to test upon.
6. Once all resources are created from the console, we'll be using the `aws cli` to retrieve the ARNs of our Device Farm project and Device Pools. Paste your Isengard credentials inside a terminal.
7. Use `aws devicefarm list-projects` to get your project's ARN. Retrieve the ARN corresponding to your project name, and run the `aws-lc/tests/ci/kickoff_devicefarm_job.sh` script with `--devicefarm-project-arn` specified with the retrieved ARN. If we're updating our team account, change the `DEVICEFARM_PROJECT` variable to the new project ARN.
8. Use `aws devicefarm  list-device-pools --arn ${project_arn}` to get your project's ARN. Retrieve the ARN corresponding to your device pool(s), and run the `aws-lc/tests/ci/kickoff_devicefarm_job.sh` script with `--devicefarm-device-pool-arn` specified with the retrieved ARN. If we're updating our team account, change the `DEVICEFARM_DEVICE_POOL` variable to the new device pool ARN.
