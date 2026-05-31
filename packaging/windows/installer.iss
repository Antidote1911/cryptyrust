#define AppName      "Cryptyrust"
#define AppPublisher "Antidote1911"
#define AppExeName   "cryptyrust.exe"
#define AppCliExe    "cryptyrust_cli.exe"
#define AppKeygenExe "crypty-keygen.exe"

[Setup]
AppId={{B8F3A2C1-4D5E-6F7A-8B9C-0D1E2F3A4B5C}
AppName={#AppName}
AppVersion={#VERSION}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputBaseFilename=cryptyrust-windows-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=icon.ico
PrivilegesRequired=admin
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french";  MessagesFile: "compiler:Languages\French.isl"

[Files]
Source: "{#AppExeName}";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppCliExe}";    DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppKeygenExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";               Filename: "{app}\{#AppExeName}"
Name: "{group}\{#AppName} CLI";           Filename: "{app}\{#AppCliExe}"
Name: "{group}\crypty-keygen";            Filename: "{app}\{#AppKeygenExe}"
Name: "{group}\Uninstall {#AppName}";     Filename: "{uninstallexe}"

; Add {app} to the system PATH so cryptyrust_cli is available from any terminal
[Registry]
Root: HKLM; \
  Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; \
  Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(
    HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
