# BouncyCastle registers its algorithms by class name, and sshj looks its
# factories up through it, so R8 cannot see they are used.
-keep class org.bouncycastle.** { *; }
-keep class net.schmizz.** { *; }
-keep class com.hierynomus.** { *; }
# Optional sshj and BouncyCastle features that are absent on Android.
-dontwarn org.ietf.jgss.**
-dontwarn javax.naming.**
-dontwarn javax.security.auth.login.**
-dontwarn com.jcraft.jzlib.**
-dontwarn org.slf4j.impl.**
