# R8 shrinks the release build from 2.2 MB to ~110 KB. The app has no reflection, no
# serialization and no libraries, and everything entered from outside (MainActivity,
# AgentService, StartReceiver) is declared in the manifest, which R8 keeps automatically.
# So there are no -keep rules, on purpose: one added "to be safe" would only hide a real
# problem. Re-test the manifest-reached paths on a device after any change here
# (approval, Deny from the notification, restart on update): docs/RELEASING.md.

# Keep file names and line numbers so a release stack trace can be decoded with the
# mapping.txt that CI publishes beside the APK.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
