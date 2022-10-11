unit Execute.Win.CryptString;

{
  (c)2018 Execute SARL
  Add function CryptStringBase64 and DecryptStringBase64 by
  Alexandre ZANELLI 2020
}

interface

uses
  Winapi.Windows,
  System.SysUtils;

function CryptString(const Str: string): TBytes;
function CryptStringBase64(const Str: string): string;
function DecryptString(const Data: TBytes): string;
function DecryptStringBase64(const Data: string): string;

implementation

uses
  System.NetEncoding;

type
  DATA_BLOB = record
    cbData :DWORD;
    pbData :PAnsiChar; // PBYTE but PAnsiChar is better for debug purpose
  end;
  PDATA_BLOB = ^DATA_BLOB;

function CryptProtectData(
  var pDataIn         : DATA_BLOB;
      ppszDataDescr   : PChar;
      pOptionalEntropy: PDATA_BLOB;
      pvReserved      : Integer;
      pPromptStruct   : Pointer; // PCRYPTPROTECT_PROMPTSTRUCT;
      dwFlags         : DWORD;
  var pDataOut        : DATA_BLOB
): BOOL; stdcall; external 'crypt32.dll';

function CryptUnprotectData(
  var pDataIn         : DATA_BLOB;
      ppszDataDescr   : PPChar;
      pOptionalEntropy: PDATA_BLOB;
      pvReserved      : Integer;
      pPromptStruct   : Pointer; // PCRYPTPROTECT_PROMPTSTRUCT;
      dwFlags         : DWORD;
  var pDataOut        : DATA_BLOB
): BOOL; stdcall; external 'crypt32.dll';

function CryptString(const Str: string): TBytes;
var
  DataIn  : DATA_BLOB;
  DataOut : DATA_BLOB;
begin
  if Str = '' then
    Exit(nil);

  DataIn.cbData := Length(Str) * SizeOf(Char);
  DataIn.pbData := Pointer(Str);

  if CryptProtectData(DataIn, 'Execute.Win.CryptString', nil, 0, nil, 0, DataOut) = False then
    RaiseLastOSError;

  SetLength(Result, DataOut.cbData);
  Move(DataOut.pbData^, Result[0], DataOut.cbData);
  LocalFree(NativeUInt(DataOut.pbData));
end;

function CryptStringBase64(const Str: string): string;
var
  Base64Encoding: TBase64Encoding;
  Crypted: TBytes;
begin
  Base64Encoding := TBase64Encoding.Create(0);
  try
    Crypted := CryptString(Str);
    Result := Base64Encoding.EncodeBytesToString(Crypted);
  finally
    Base64Encoding.Free;
  end;
end;

function DecryptString(const Data: TBytes): string;
var
  DataIn  : DATA_BLOB;
  DataOut : DATA_BLOB;
begin
  if Data = nil then
    Exit('');

  DataIn.cbData := Length(Data);
  DataIn.pbData := Pointer(Data);

  if CryptUnprotectData(DataIn, nil, nil, 0, nil, 0, DataOut) = False then
    RaiseLastOSError;

  SetLength(Result, DataOut.cbData div SizeOf(Char));
  Move(DataOut.pbData^, Pointer(Result)^, DataOut.cbData);
  LocalFree(NativeUInt(DataOut.pbData));
end;

function DecryptStringBase64(const Data: string): string;
var
  Base64Encoding: TBase64Encoding;
  Crypted: TBytes;
begin
  Base64Encoding := TBase64Encoding.Create(0);
  try
    Crypted := Base64Encoding.DecodeStringToBytes(Data);
    Result := DecryptString(Crypted);
  finally
    Base64Encoding.Free;
  end;
end;

end.