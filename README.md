# CERNmap
Offline map of CERN for mobile devices. It should work on pretty much any mobile platform as it is based on Apache Cordova.

![Alt text](screen0.jpg?raw=true "Screenshot 0")
![Alt text](screen1.jpg?raw=true "Screenshot 1")
![Alt text](screen2.jpg?raw=true "Screenshot 2")

# Building

`npm install -g cordova`

## Android
Depending on your target SDK version, have either `ANDROID_HOME` or `ANDROID_SDK_ROOT` variable set.
```
cordova add platform android`
cordova run android
```

## iOS
```
cordova add platform ios
cordova run ios
```
