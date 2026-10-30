#!/usr/bin/env python3
"""Generate the two-target Xcode project using only Python's standard library."""
from pathlib import Path
import hashlib
import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--backend", choices=["standalone", "network-extension"], default="standalone")
parser.add_argument("--trusttunnel", action="store_true")
args = parser.parse_args()
backend = args.backend
trusttunnel = args.trusttunnel
if trusttunnel and backend != "network-extension": parser.error("TrustTunnel requires NetworkExtension")
standalone = backend == "standalone"

root = Path(__file__).resolve().parents[1]
objects = {}
def identifier(name): return hashlib.sha256(name.encode()).hexdigest()[:24].upper()
def obj(object_name, isa, **fields):
    key = identifier(object_name)
    objects[key] = dict(isa=isa, **fields)
    return key

def file(path, kind):
    return obj('file:'+path, 'PBXFileReference', lastKnownFileType=kind, path=path, sourceTree='<group>')
base = file('Config/Base.xcconfig', 'text.xcconfig')
core = obj('package:Core', 'XCLocalSwiftPackageReference', relativePath='Core')
awg = obj('package:AWG', 'XCLocalSwiftPackageReference', relativePath='.build-deps/AWGKit')
sparkle = obj('package:Sparkle', 'XCRemoteSwiftPackageReference', repositoryURL='https://github.com/sparkle-project/Sparkle', requirement={'kind':'exactVersion','version':json.loads((root/'dependency-lock.json').read_text())['sparkleVersion']})
products = []
targets = []
children = [base]
if trusttunnel:
    tt = file('.build-deps/TrustTunnel/VpnClientFramework.framework', 'wrapper.framework')
    children.append(tt)
for folder in (['App'] if standalone else ['App', 'Tunnel']):
    refs = [file(str(p.relative_to(root)), 'sourcecode.swift') for p in sorted((root/folder).rglob('*.swift'))]
    children.extend(refs)
    sources = obj(folder+':sources','PBXSourcesBuildPhase',buildActionMask=2147483647,
        files=[obj(folder+':build:'+r,'PBXBuildFile',fileRef=r) for r in refs],runOnlyForDeploymentPostprocessing=0)
    deps = [obj(folder+':product:Core','XCSwiftPackageProductDependency',package=core,productName='UndercoreMacCore'),
            obj(folder+':product:AWG','XCSwiftPackageProductDependency',package=awg,productName='WireGuardKit')]
    if folder == 'App':
        deps = deps[:1] + [obj('App:product:Sparkle', 'XCSwiftPackageProductDependency', package=sparkle, productName='Sparkle')]
    frameworks=obj(folder+':frameworks','PBXFrameworksBuildPhase',buildActionMask=2147483647,
        files=[obj(folder+':link:'+r,'PBXBuildFile',productRef=r) for r in deps],runOnlyForDeploymentPostprocessing=0)
    if trusttunnel and folder == 'Tunnel':
        objects[frameworks]['files'].append(obj('Tunnel:TrustTunnel:link', 'PBXBuildFile', fileRef=tt))
    configurations=[]
    for mode in ['Debug','Release']:
        settings={'PRODUCT_NAME':'Undercore' if folder=='App' else 'ru.undercore.macos.tunnel',
            'PRODUCT_MODULE_NAME':'Undercore' if folder=='App' else 'UndercoreTunnel',
            'PRODUCT_BUNDLE_IDENTIFIER':'ru.undercore.macos' + ('.tunnel' if folder=='Tunnel' else ''),
            'INFOPLIST_FILE':f'Config/{folder}-Info.plist','CODE_SIGN_ENTITLEMENTS':f'Config/{folder}.entitlements',
            'SWIFT_OPTIMIZATION_LEVEL':'-Onone' if mode=='Debug' else '-O',
            'SWIFT_ACTIVE_COMPILATION_CONDITIONS':('DEBUG ' if mode=='Debug' else '') + ('' if standalone else 'USE_NETWORK_EXTENSION'),
            'LD_RUNPATH_SEARCH_PATHS':['$(inherited)','@executable_path/../Frameworks'],
            'GENERATE_INFOPLIST_FILE':'NO','SKIP_INSTALL':'NO' if folder=='App' else 'YES'}
        if trusttunnel:
            settings['SWIFT_ACTIVE_COMPILATION_CONDITIONS'] += ' TRUSTTUNNEL_EXPERIMENTAL'
            settings['FRAMEWORK_SEARCH_PATHS'] = ['$(inherited)', '$(SRCROOT)/.build-deps/TrustTunnel']
        if standalone:
            settings.update(CODE_SIGN_ENTITLEMENTS='Config/Standalone.entitlements', CODE_SIGN_IDENTITY='-', CODE_SIGN_STYLE='Manual', DEVELOPMENT_TEAM='')
            if mode == 'Release': settings['CODE_SIGN_INJECT_BASE_ENTITLEMENTS'] = 'NO'
        if folder=='App':
            settings['ASSETCATALOG_COMPILER_APPICON_NAME']='AppIcon'
            settings['UNDERCORE_UPDATE_BACKEND'] = backend
        if folder=='Tunnel': settings['APPLICATION_EXTENSION_API_ONLY']='YES'
        configurations.append(obj(folder+':'+mode,'XCBuildConfiguration',name=mode,baseConfigurationReference=base,buildSettings=settings))
    configlist=obj(folder+':configs','XCConfigurationList',buildConfigurations=configurations,defaultConfigurationIsVisible=0,defaultConfigurationName='Debug')
    product=obj(folder+':output','PBXFileReference',explicitFileType='wrapper.application' if folder=='App' else 'wrapper.system-extension',
        path='Undercore.app' if folder=='App' else 'ru.undercore.macos.tunnel.systemextension',sourceTree='BUILT_PRODUCTS_DIR',includeInIndex=0)
    products.append(product)
    target=obj(folder+':target','PBXNativeTarget',buildConfigurationList=configlist,buildPhases=[sources,frameworks],buildRules=[],dependencies=[],
        name='Undercore' if folder=='App' else 'UndercoreTunnel',productName='Undercore' if folder=='App' else 'UndercoreTunnel',productReference=product,
        productType='com.apple.product-type.application' if folder=='App' else 'com.apple.product-type.system-extension',packageProductDependencies=deps)
    if trusttunnel and folder == 'Tunnel':
        objects[target]['buildPhases'].append(obj('embedTrustTunnel', 'PBXCopyFilesBuildPhase',
            buildActionMask=2147483647, dstPath='', dstSubfolderSpec=10, runOnlyForDeploymentPostprocessing=0,
            files=[obj('TrustTunnel:embed', 'PBXBuildFile', fileRef=tt,
                settings={'ATTRIBUTES':['CodeSignOnCopy','RemoveHeadersOnCopy']})]))
    targets.append(target)
if not standalone:
    proxy=obj('tunnelProxy','PBXContainerItemProxy',containerPortal=identifier('project'),proxyType=1,remoteGlobalIDString=targets[1],remoteInfo='UndercoreTunnel')
    objects[targets[0]]['dependencies']=[obj('tunnelDependency','PBXTargetDependency',target=targets[1],targetProxy=proxy)]
    objects[targets[0]]['buildPhases'].append(obj('embedTunnel','PBXCopyFilesBuildPhase',buildActionMask=2147483647,dstPath='$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions',dstSubfolderSpec=16,
        files=[obj('embedTunnelFile','PBXBuildFile',fileRef=products[1],settings={'ATTRIBUTES':['CodeSignOnCopy','RemoveHeadersOnCopy']})],name='Embed System Extension',runOnlyForDeploymentPostprocessing=0))
resources=[]
ref=file('App/Assets.xcassets','folder.assetcatalog')
children.append(ref)
resources.append(obj('resource:App/Assets.xcassets','PBXBuildFile',fileRef=ref))
for path in ['Config/ThirdPartyNotices.txt'] + (['.build/standalone/undercore-helper'] if standalone else []):
    ref=file(path,'text');children.append(ref);resources.append(obj('resource:'+path,'PBXBuildFile',fileRef=ref))
objects[targets[0]]['buildPhases'].append(obj('resources','PBXResourcesBuildPhase',buildActionMask=2147483647,files=resources,runOnlyForDeploymentPostprocessing=0))
pg=obj('products','PBXGroup',children=products,name='Products',sourceTree='<group>')
group=obj('mainGroup','PBXGroup',children=[*children,pg],sourceTree='<group>')
configs=[obj('project:'+mode,'XCBuildConfiguration',name=mode,baseConfigurationReference=base,
    buildSettings={'SDKROOT':'macosx','CLANG_ENABLE_MODULES':'YES','CLANG_ENABLE_OBJC_ARC':'YES','ONLY_ACTIVE_ARCH':'YES' if mode=='Debug' else 'NO'}) for mode in ['Debug','Release']]
configlist=obj('project:configs','XCConfigurationList',buildConfigurations=configs,defaultConfigurationIsVisible=0,defaultConfigurationName='Debug')
project=obj('project','PBXProject',attributes={'BuildIndependentTargetsInParallel':'YES','LastUpgradeCheck':'2700'},buildConfigurationList=configlist,compatibilityVersion='Xcode 14.0',developmentRegion='ru',knownRegions=['ru','en','Base'],mainGroup=group,productRefGroup=pg,projectDirPath='',projectRoot='',targets=targets,packageReferences=[core,awg,sparkle])
def render(value):
    if isinstance(value,dict): return '{\n'+'\n'.join(json.dumps(k)+' = '+render(v)+';' for k,v in value.items())+'\n}'
    if isinstance(value,list): return '('+', '.join(render(v) for v in value)+')'
    if isinstance(value,int): return str(value)
    return json.dumps(value,ensure_ascii=False)
folder=root/'Undercore.xcodeproj';folder.mkdir(exist_ok=True)
(folder/'project.pbxproj').write_text('// !$*UTF8*$!\n'+render({'archiveVersion':1,'classes':{},'objectVersion':56,'objects':objects,'rootObject':project})+'\n')
schemes=folder/'xcshareddata/xcschemes';schemes.mkdir(parents=True,exist_ok=True)
(schemes/'Undercore.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{targets[0]}" BuildableName="Undercore.app" BlueprintName="Undercore" ReferencedContainer="container:Undercore.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction>
 <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="NO"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{targets[0]}" BuildableName="Undercore.app" BlueprintName="Undercore" ReferencedContainer="container:Undercore.xcodeproj"/></BuildableProductRunnable></LaunchAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
print('Generated Xcode project for', backend)
