package app.revanced.patches.grindr.spoof.patch

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.patch.options.PatchOption.PatchExtensions.stringPatchOption
import app.revanced.patches.grindr.spoof.fingerprints.GetAndroidIDFingerprint

@Patch(
    name = "Spoof Android device ID",
    description = "Spoofs the Android device ID used by the app for account authentication. " +
        "This can be used to copy the account to another device.",
    compatiblePackages = [
        CompatiblePackage(
            "com.grindrapp.android",
            [
                "24.9.0",
                "24.10.0",
                "24.11.0",
                "24.12.0",
                "24.13.0",
            ],
        ),
    ]
)


object SpoofAndroidDeviceIdPatch : BytecodePatch(
    setOf(GetAndroidIDFingerprint),
) {
    private var androidDeviceId =
        stringPatchOption(
            key = "android-device-id",
            default = "0011223344556677",
            title = "Android device ID",
            description = "The Android device ID to spoof to.",
            required = true,
        ) { it!!.matches("[A-Fa-f0-9]{16}".toRegex()) }

    override fun execute(context: BytecodeContext) = GetAndroidIDFingerprint.result?.mutableMethod?.addInstructions(
        0,
        """
            const-string v0, "$androidDeviceId"
            return-object v0
        """,
    )
}