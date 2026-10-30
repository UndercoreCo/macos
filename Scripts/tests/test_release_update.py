import copy
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
import release_update as release

class ReleaseValidationTests(unittest.TestCase):
    def info(self):
        return {'CFBundleIdentifier':'ru.undercore.macos','CFBundleVersion':'4',
                'SUPublicEDKey':release.PUBLIC_KEY,'SUFeedURL':release.FEED,
                'SURequireSignedFeed':True,'SUVerifyUpdateBeforeExtraction':True,
                'SUAllowsAutomaticUpdates':False,'UndercoreUpdatesEnabled':'YES'}

    def test_refuses_unsigned_wrong_feed_or_silent_updates(self):
        for key,value in [('SURequireSignedFeed',False),('SUVerifyUpdateBeforeExtraction',False),
                          ('SUPublicEDKey','foreign'),('SUFeedURL','http://example.com/feed'),
                          ('SUAllowsAutomaticUpdates',True),('UndercoreUpdatesEnabled','NO'),
                          ('CFBundleVersion','3'),('CFBundleVersion','4.0'),('CFBundleIdentifier','other')]:
            with self.subTest(key=key):
                info=self.info();info[key]=value
                with self.assertRaises(ValueError):release.validate_info(info)

    def test_accepts_expected_signed_test_channel(self):
        release.validate_info(self.info())

    def profile(self):
        return {'ProvisionsAllDevices':True,'TeamIdentifier':[release.TEAM],
                'Entitlements':{'com.apple.developer.networking.networkextension':['packet-tunnel-provider-systemextension']}}

    def test_development_profile_cannot_be_published(self):
        profile=self.profile();profile['ProvisionedDevices']=['synthetic-device']
        with self.assertRaises(ValueError):release.validate_profile(profile)
        profile=self.profile();profile['ProvisionsAllDevices']=False
        with self.assertRaises(ValueError):release.validate_profile(profile)

    def test_foreign_team_debug_and_wrong_extension_entitlement_rejected(self):
        profile=self.profile();profile['TeamIdentifier']=['OTHER']
        with self.assertRaises(ValueError):release.validate_profile(profile)
        for change in [{'get-task-allow':True}, {'com.apple.security.get-task-allow':True},
                       {'com.apple.developer.networking.networkextension':['packet-tunnel-provider']}]:
            profile=self.profile();profile['Entitlements'].update(change)
            with self.assertRaises(ValueError):release.validate_profile(profile)

    def test_distribution_profile_is_accepted(self):
        release.validate_profile(self.profile())

if __name__=='__main__':unittest.main()
