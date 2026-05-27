[Setup]
AppName=QuicProxy
AppVersion=0.1.0
DefaultDirName={autopf}\QuicProxy
DefaultGroupName=QuicProxy
OutputDir=Output
OutputBaseFilename=QuicProxy-Windows-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\quicproxy_flutter.exe

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "cn"; MessagesFile: "cn.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "quicproxy_flutter\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\QuicProxy"; Filename: "{app}\quicproxy_flutter.exe"
Name: "{autodesktop}\QuicProxy"; Filename: "{app}\quicproxy_flutter.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\quicproxy_flutter.exe"; Description: "{cm:LaunchProgram,QuicProxy}"; Flags: nowait postinstall skipifsilent
