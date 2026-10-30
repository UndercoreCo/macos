#!/usr/bin/env python3
"""Export, notarize, staple and sign a local test-channel update. Never publishes it."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from prepare_updates import prepare

PUBLIC_KEY = 'ECgltqKsFm40dxp1CHAoqa76p5V4Id/yAbRizD/246g='
KEY_ACCOUNT = 'ru.undercore.macos.updates'
TEAM = '5XU62DD2N8'
FEED = 'https://undercore.ru/updates/macos/network-extension/test/appcast.xml'

def validate_info(info):
    if info.get('CFBundleIdentifier') != 'ru.undercore.macos':
        raise ValueError('Unexpected application identity')
    if not re.fullmatch(r'[1-9][0-9]{0,9}', info.get('CFBundleVersion', '')) or not 4 <= int(info['CFBundleVersion']) <= 2147483647:
        raise ValueError('Invalid monotonic build number')
    if info.get('SUPublicEDKey') != PUBLIC_KEY or info.get('SUFeedURL') != FEED:
        raise ValueError('Unexpected update signing key or feed')
    for key in ('SURequireSignedFeed', 'SUVerifyUpdateBeforeExtraction'):
        if info.get(key) is not True: raise ValueError('Signed feed and archive verification required')
    if info.get('SUAllowsAutomaticUpdates') is not False or info.get('UndercoreUpdatesEnabled') != 'YES':
        raise ValueError('Updates must be enabled without silent installation')

def validate_profile(profile):
    entitlement = profile.get('Entitlements', {})
    if profile.get('ProvisionsAllDevices') is not True or profile.get('ProvisionedDevices'):
        raise ValueError('Developer ID distribution profile required; development profiles are not publishable')
    if TEAM not in profile.get('TeamIdentifier', []) or entitlement.get('get-task-allow', entitlement.get('com.apple.security.get-task-allow', False)):
        raise ValueError('Unexpected team or debugging entitlement')
    if 'packet-tunnel-provider-systemextension' not in entitlement.get('com.apple.developer.networking.networkextension', []):
        raise ValueError('Developer ID system-extension entitlement required')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New private release directory')
    parser.add_argument('--notary-profile', help='Optional notarytool Keychain profile; otherwise use the signed-in Xcode account')
    parser.add_argument('--notarized-app', type=Path, help='Resume packaging an already exported notarized app; it is verified again')
    parser.add_argument('--notes', type=Path, required=True, help='Release notes from docs/internal or docs/public')
    args=parser.parse_args()
    archive=args.archive.expanduser().resolve();out=args.output.expanduser().resolve()
    if not archive.is_dir() or archive.suffix != '.xcarchive' or out.exists():
        parser.error('Expected existing xcarchive and a new output directory')
    source=archive/'Products/Applications/Undercore.app'
    info=plistlib.loads((source/'Contents/Info.plist').read_bytes());validate_info(info)
    if not args.notes.is_file(): parser.error('Release notes are required')
    os.umask(0o077);out.mkdir(parents=True)
    def run(label,command):
        result=subprocess.run(command,capture_output=True,timeout=900)
        (out/(label+'.log')).write_bytes(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError(label+' failed; inspect its private log')
        return result.stdout
    tools=prepare()
    public=run('signing-key',[str(tools/'bin/generate_keys'),'--account',KEY_ACCOUNT,'-p']).decode().strip()
    if public != PUBLIC_KEY: raise ValueError('Signing key does not match application')
    options=out/'ExportOptions.plist'
    options.write_bytes(plistlib.dumps({'method':'developer-id','teamID':TEAM,'signingStyle':'automatic','manageAppVersionAndBuildNumber':False}))
    if not args.notarized_app: run('export',['xcodebuild','-exportArchive','-archivePath',str(archive),'-exportPath',str(out/'export'),'-exportOptionsPlist',str(options),'-allowProvisioningUpdates'])
    app=args.notarized_app.expanduser().resolve() if args.notarized_app else out/'export/Undercore.app'
    exported_info=plistlib.loads((app/'Contents/Info.plist').read_bytes());validate_info(exported_info)
    if exported_info['CFBundleVersion'] != info['CFBundleVersion']:
        raise ValueError('Export changed the approved build number')
    extension=app/'Contents/Library/SystemExtensions/ru.undercore.macos.tunnel.systemextension'
    for index,bundle in enumerate((app,extension)):
        run('verify-'+str(index),['codesign','--verify','--deep','--strict',str(bundle)])
        details=subprocess.run(['codesign','-dvv',str(bundle)],capture_output=True,check=True).stderr.decode()
        if 'Authority=Developer ID Application:' not in details or 'TeamIdentifier='+TEAM not in details:
            raise ValueError('Developer ID signature required on app and extension')
        profile=plistlib.loads(run('profile-'+str(index),['security','cms','-D','-i',str(bundle/'Contents/embedded.provisionprofile')]))
        validate_profile(profile)
        entitlements=plistlib.loads(run('entitlements-'+str(index),['codesign','-d','--entitlements',':-',str(bundle)]))
        if 'packet-tunnel-provider-systemextension' not in entitlements.get('com.apple.developer.networking.networkextension',[]):
            raise ValueError('Distribution entitlement missing from signature')
    ticket = {}
    if args.notarized_app:
        pass
    elif args.notary_profile:
        upload=out/'notary-upload.zip'
        run('zip-for-notary',['ditto','-c','-k','--keepParent',str(app),str(upload)])
        response=run('notarization',['xcrun','notarytool','submit',str(upload),'--keychain-profile',args.notary_profile,'--wait','--timeout','10m','--output-format','json'])
        ticket=json.loads(response)
        if ticket.get('status') != 'Accepted': raise ValueError('Notarization not accepted; no update feed generated')
        run('staple',['xcrun','stapler','staple',str(app)])
    else:
        upload_options=out/'UploadOptions.plist'
        upload_options.write_bytes(plistlib.dumps({'method':'developer-id','destination':'upload','teamID':TEAM,'signingStyle':'automatic','manageAppVersionAndBuildNumber':False}))
        run('notarization-upload',['xcodebuild','-exportArchive','-archivePath',str(archive),'-exportPath',str(out/'submission'),'-exportOptionsPlist',str(upload_options),'-allowProvisioningUpdates'])
        # Pending approval fails here without publishing. Resume with --notarized-app
        # after exporting the accepted archive with xcodebuild -exportNotarizedApp.
        run('notarized-export',['xcodebuild','-exportNotarizedApp','-archivePath',str(archive),'-exportPath',str(out/'notarized')])
        accepted=out/'notarized/Undercore.app'
        run('verify-notarized',['codesign','--verify','--deep','--strict',str(accepted)])
        accepted_info=plistlib.loads((accepted/'Contents/Info.plist').read_bytes());validate_info(accepted_info)
        if accepted_info['CFBundleVersion'] != info['CFBundleVersion']: raise ValueError('Notarized version mismatch')
        app=accepted
    run('validate-ticket',['xcrun','stapler','validate',str(app)])
    run('gatekeeper',['spctl','--assess','--type','execute',str(app)])
    public_dir=out/'public';public_dir.mkdir()
    name='Undercore-'+info['CFBundleVersion']
    package=public_dir/(name+'.zip')
    run('zip-release',['ditto','-c','-k','--keepParent',str(app),str(package)])
    notes='<html><body><pre style="white-space:pre-wrap">'+html.escape(args.notes.read_text())+'</pre></body></html>'
    (public_dir/(name+'.html')).write_text(notes)
    run('appcast',[str(tools/'bin/generate_appcast'),'--account',KEY_ACCOUNT,'--download-url-prefix',FEED.rsplit('/',1)[0]+'/', '--embed-release-notes','--maximum-deltas','0',str(public_dir)])
    feed=ET.parse(public_dir/'appcast.xml');items=feed.findall('./channel/item')
    namespace='{http://www.andymatuschak.org/xml-namespaces/sparkle}'
    if len(items)!=1 or items[0].findtext(namespace+'version') != info['CFBundleVersion']:
        raise ValueError('Unexpected appcast version')
    enclosure=items[0].find('enclosure')
    if not enclosure.get(namespace+'edSignature') or enclosure.get('length') != str(package.stat().st_size):
        raise ValueError('Unsigned or inconsistent archive')
    run('verify-feed-signature',[str(tools/'bin/sign_update'),'--account',KEY_ACCOUNT,'--verify',str(public_dir/'appcast.xml')])
    run('verify-archive-signature',[str(tools/'bin/sign_update'),'--account',KEY_ACCOUNT,'--verify',str(package),enclosure.get(namespace+'edSignature')])
    proof={'build':info['CFBundleVersion'],'version':info['CFBundleShortVersionString'],'notarization_id':ticket.get('id'), 'notarized':True,'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'feed':FEED,'published':False}
    (out/'verified.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof))
    print('Only files in public/ may be published. Upload archive before appcast, replacing the feed atomically.')

if __name__=='__main__':
    main()
