{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  CRC32 calculation (polynomial 0x04C11DB7)

  Version 1.5.1 (2020-03-29)

  Last change 2020-03-29

  ©2011-2020 František Milt

  Contacts:
    František Milt: frantisek.milt@gmail.com

  Support:
    If you find this code useful, please consider supporting its author(s) by
    making a small donation using the following link(s):

      https://www.paypal.me/FMilt

  Changelog:
    For detailed changelog and history please refer to this git repository:

      github.com/TheLazyTomcat/Lib.CRC32

  Dependencies:
    AuxTypes           - github.com/TheLazyTomcat/Lib.AuxTypes
    HashBase           - github.com/TheLazyTomcat/Lib.HashBase
    AuxClasses         - github.com/TheLazyTomcat/Lib.AuxClasses
    StrRect            - github.com/TheLazyTomcat/Lib.StrRect
    StaticMemoryStream - github.com/TheLazyTomcat/Lib.StaticMemoryStream

===============================================================================}
unit CRC32;

{
  CRC32_PurePascal

  If you want to compile this unit without ASM, don't want to or cannot define
  PurePascal for the entire project and at the same time you don't want to or
  cannot make changes to this unit, define this symbol for the entire project
  and this unit will be compiled in PurePascal mode.
}
{$IFDEF CRC32_PurePascal}
  {$DEFINE PurePascal}
{$ENDIF}

{$IF defined(CPUX86_64) or defined(CPUX64)}
  {$DEFINE x64}
{$ELSEIF defined(CPU386)}
  {$DEFINE x86}
{$ELSE}
  {$DEFINE PurePascal}
{$IFEND}

{$IF Defined(WINDOWS) or Defined(MSWINDOWS)}
  {$DEFINE Windows}
{$IFEND}

{$IFDEF FPC}
  {$MODE ObjFPC}{$H+}{$MODESWITCH CLASSICPROCVARS+}
  {$DEFINE FPC_DisableWarns}
  {$MACRO ON}  
  {$IFNDEF PurePascal}
    {$ASMMODE Intel}
  {$ENDIF}
{$ENDIF}

interface

uses
  Classes,
  AuxTypes, HashBase;

{===============================================================================
    Common types and constants
===============================================================================}

{
  Note that type TCRC32 contains individual bytes of the checksum in the same
  order as they are presented in its textual representation. That means most
  significant byte first (left), least significant byte last (righ).

  Type TCRC32Sys has no such guarantee and its endianness is system-dependent.

  To convert the checksum in default ordering to a required specific ordering,
  use methods CRC32ToLE for little endian and CRC32ToBE for big endian.
  Note that these methods are expecting the input value to be in default
  ordering, if it is not, the result will be wrong. Be carefull when using them.
}
type
  TCRC32 = array[0..3] of UInt8;
  PCRC32 = ^TCRC32;

  TCRC32Sys = UInt32;
  PCRC32Sys = ^TCRC32Sys;

const
  InitialCRC32: TCRC32 = ($00,$00,$00,$00);

type
  ECRC32Exception = class(EHashException);

  ECRC32IncompatibleClass = class(ECRC32Exception);

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32Hash - class declaration
===============================================================================}
type
  TCRC32Hash = class(TStreamHash)
  private
    fCRC32:         TCRC32Sys;
    fProcessBuffer: procedure(const Buffer; Size: TMemSize) of object; register;
    Function GetCRC32: TCRC32;
  protected
    Function GetHashImplementation: THashImplementation; override;
    procedure SetHashImplementation(Value: THashImplementation); override;  
  {$IFNDEF PurePascal}
    procedure ProcessBuffer_ASM(const Buffer; Size: TMemSize); virtual; register;
  {$ENDIF}
    procedure ProcessBuffer_PAS(const Buffer; Size: TMemSize); virtual; register;
    procedure ProcessBuffer(const Buffer; Size: TMemSize); override;
    procedure Initialize; override;
  public
    class Function CRC32ToSys(CRC32: TCRC32): TCRC32Sys; virtual;
    class Function CRC32FromSys(CRC32: TCRC32Sys): TCRC32; virtual;
    class Function CRC32ToLE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32ToBE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32FromLE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32FromBE(CRC32: TCRC32): TCRC32; virtual;
    class Function HashSize: TMemSize; override;
    class Function HashName: String; override;
    class Function HashEndianness: THashEndianness; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TCRC32); overload; virtual;
    procedure Init; override;
    Function Compare(Hash: THashBase): Integer; override;
    Function AsString: String; override;
    procedure FromString(const Str: String); override;
    procedure FromStringDef(const Str: String; const Default: TCRC32); reintroduce;
    procedure SaveToStream(Stream: TStream; Endianness: THashEndianness = heDefault); override;
    procedure LoadFromStream(Stream: TStream; Endianness: THashEndianness = heDefault); override;
    property CRC32: TCRC32 read GetCRC32;
    property CRC32Sys: TCRC32Sys read fCRC32;
  end;

{===============================================================================
    Backward compatibility functions
===============================================================================}

Function CRC32ToStr(CRC32: TCRC32): String;
Function StrToCRC32(const Str: String): TCRC32;
Function TryStrToCRC32(const Str: String; out CRC32: TCRC32): Boolean;
Function StrToCRC32Def(const Str: String; Default: TCRC32): TCRC32;

Function CompareCRC32(A,B: TCRC32): Integer;
Function SameCRC32(A,B: TCRC32): Boolean;

//------------------------------------------------------------------------------

Function BufferCRC32(CRC32: TCRC32; const Buffer; Size: TMemSize): TCRC32; overload;

Function BufferCRC32(const Buffer; Size: TMemSize): TCRC32; overload;

Function AnsiStringCRC32(const Str: AnsiString): TCRC32;
Function WideStringCRC32(const Str: WideString): TCRC32;
Function StringCRC32(const Str: String): TCRC32;

Function StreamCRC32(Stream: TStream; Count: Int64 = -1): TCRC32;
Function FileCRC32(const FileName: String): TCRC32;

//------------------------------------------------------------------------------

type
  TCRC32Context = type Pointer;

Function CRC32_Init: TCRC32Context;
procedure CRC32_Update(Context: TCRC32Context; const Buffer; Size: TMemSize);
Function CRC32_Final(var Context: TCRC32Context; const Buffer; Size: TMemSize): TCRC32; overload;
Function CRC32_Final(var Context: TCRC32Context): TCRC32; overload;
Function CRC32_Hash(const Buffer; Size: TMemSize): TCRC32;

implementation

uses
  SysUtils;

{$IFDEF FPC_DisableWarns}
  {$DEFINE FPCDWM}
  {$DEFINE W5057:={$WARN 5057 OFF}} // Local variable "$1" does not seem to be initialized
{$ENDIF}

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32Hash
================================================================================
-------------------------------------------------------------------------------}

{===============================================================================
    TCRC32Hash - utility functions
===============================================================================}

Function SwapEndian(Value: TCRC32Sys): TCRC32Sys; overload;
begin
Result := TCRC32Sys(
  ((Value and $000000FF) shl 24) or
  ((Value and $0000FF00) shl 8) or
  ((Value and $00FF0000) shr 8) or
  ((Value and $FF000000) shr 24));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function SwapEndian(Value: TCRC32): TCRC32; overload;
begin
Result := TCRC32(SwapEndian(TCRC32Sys(Value)));
end;

{===============================================================================
    TCRC32Hash - calculation constants
===============================================================================}

const
  CRCTable: Array[Byte] of TCRC32Sys = (
    $00000000, $77073096, $EE0E612C, $990951BA, $076DC419, $706AF48F, $E963A535, $9E6495A3,
    $0EDB8832, $79DCB8A4, $E0D5E91E, $97D2D988, $09B64C2B, $7EB17CBD, $E7B82D07, $90BF1D91,
    $1DB71064, $6AB020F2, $F3B97148, $84BE41DE, $1ADAD47D, $6DDDE4EB, $F4D4B551, $83D385C7,
    $136C9856, $646BA8C0, $FD62F97A, $8A65C9EC, $14015C4F, $63066CD9, $FA0F3D63, $8D080DF5,
    $3B6E20C8, $4C69105E, $D56041E4, $A2677172, $3C03E4D1, $4B04D447, $D20D85FD, $A50AB56B,
    $35B5A8FA, $42B2986C, $DBBBC9D6, $ACBCF940, $32D86CE3, $45DF5C75, $DCD60DCF, $ABD13D59,
    $26D930AC, $51DE003A, $C8D75180, $BFD06116, $21B4F4B5, $56B3C423, $CFBA9599, $B8BDA50F,
    $2802B89E, $5F058808, $C60CD9B2, $B10BE924, $2F6F7C87, $58684C11, $C1611DAB, $B6662D3D,
    $76DC4190, $01DB7106, $98D220BC, $EFD5102A, $71B18589, $06B6B51F, $9FBFE4A5, $E8B8D433,
    $7807C9A2, $0F00F934, $9609A88E, $E10E9818, $7F6A0DBB, $086D3D2D, $91646C97, $E6635C01,
    $6B6B51F4, $1C6C6162, $856530D8, $F262004E, $6C0695ED, $1B01A57B, $8208F4C1, $F50FC457,
    $65B0D9C6, $12B7E950, $8BBEB8EA, $FCB9887C, $62DD1DDF, $15DA2D49, $8CD37CF3, $FBD44C65,
    $4DB26158, $3AB551CE, $A3BC0074, $D4BB30E2, $4ADFA541, $3DD895D7, $A4D1C46D, $D3D6F4FB,
    $4369E96A, $346ED9FC, $AD678846, $DA60B8D0, $44042D73, $33031DE5, $AA0A4C5F, $DD0D7CC9,
    $5005713C, $270241AA, $BE0B1010, $C90C2086, $5768B525, $206F85B3, $B966D409, $CE61E49F,
    $5EDEF90E, $29D9C998, $B0D09822, $C7D7A8B4, $59B33D17, $2EB40D81, $B7BD5C3B, $C0BA6CAD,
    $EDB88320, $9ABFB3B6, $03B6E20C, $74B1D29A, $EAD54739, $9DD277AF, $04DB2615, $73DC1683,
    $E3630B12, $94643B84, $0D6D6A3E, $7A6A5AA8, $E40ECF0B, $9309FF9D, $0A00AE27, $7D079EB1,
    $F00F9344, $8708A3D2, $1E01F268, $6906C2FE, $F762575D, $806567CB, $196C3671, $6E6B06E7,
    $FED41B76, $89D32BE0, $10DA7A5A, $67DD4ACC, $F9B9DF6F, $8EBEEFF9, $17B7BE43, $60B08ED5,
    $D6D6A3E8, $A1D1937E, $38D8C2C4, $4FDFF252, $D1BB67F1, $A6BC5767, $3FB506DD, $48B2364B,
    $D80D2BDA, $AF0A1B4C, $36034AF6, $41047A60, $DF60EFC3, $A867DF55, $316E8EEF, $4669BE79,
    $CB61B38C, $BC66831A, $256FD2A0, $5268E236, $CC0C7795, $BB0B4703, $220216B9, $5505262F,
    $C5BA3BBE, $B2BD0B28, $2BB45A92, $5CB36A04, $C2D7FFA7, $B5D0CF31, $2CD99E8B, $5BDEAE1D,
    $9B64C2B0, $EC63F226, $756AA39C, $026D930A, $9C0906A9, $EB0E363F, $72076785, $05005713,
    $95BF4A82, $E2B87A14, $7BB12BAE, $0CB61B38, $92D28E9B, $E5D5BE0D, $7CDCEFB7, $0BDBDF21,
    $86D3D2D4, $F1D4E242, $68DDB3F8, $1FDA836E, $81BE16CD, $F6B9265B, $6FB077E1, $18B74777,
    $88085AE6, $FF0F6A70, $66063BCA, $11010B5C, $8F659EFF, $F862AE69, $616BFFD3, $166CCF45,
    $A00AE278, $D70DD2EE, $4E048354, $3903B3C2, $A7672661, $D06016F7, $4969474D, $3E6E77DB,
    $AED16A4A, $D9D65ADC, $40DF0B66, $37D83BF0, $A9BCAE53, $DEBB9EC5, $47B2CF7F, $30B5FFE9,
    $BDBDF21C, $CABAC28A, $53B39330, $24B4A3A6, $BAD03605, $CDD70693, $54DE5729, $23D967BF,
    $B3667A2E, $C4614AB8, $5D681B02, $2A6F2B94, $B40BBE37, $C30C8EA1, $5A05DF1B, $2D02EF8D);

{===============================================================================
    TCRC32Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TCRC32Hash - private methods
-------------------------------------------------------------------------------}

Function TCRC32Hash.GetCRC32: TCRC32;
begin
Result := CRC32FromSys(fCRC32);
end;

{-------------------------------------------------------------------------------
    TCRC32Hash - protected methods
-------------------------------------------------------------------------------}

Function TCRC32Hash.GetHashImplementation: THashImplementation;
begin
{$IFNDEF PurePascal}
If TMethod(fProcessBuffer).Code = @TCRC32Hash.ProcessBuffer_ASM then
  Result := himAssembly
else
{$ENDIF}
  Result := himPascal; 
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.SetHashImplementation(Value: THashImplementation);
begin
case Value of
  himAssembly:  fProcessBuffer := {$IFDEF PurePascal}ProcessBuffer_PAS{$ELSE}ProcessBuffer_ASM{$ENDIF};
else
 {himPascal}
  fProcessBuffer := ProcessBuffer_PAS;
end;
end;

//------------------------------------------------------------------------------

{$IFNDEF PurePascal}
procedure TCRC32Hash.ProcessBuffer_ASM(const Buffer; Size: TMemSize); assembler;
asm
{$IFDEF x64}
{$IFDEF Windows}
{-------------------------------------------------------------------------------
  x86-64 assembly (64bit) - Windows

  Content of registers on enter:

    RCX   Self
    RDX   pointer to Buffer
    R8    Size

  Used registers:
    RAX, RCX, RDX, R8, R9, R10
-------------------------------------------------------------------------------}

                LEA   RCX, Self.fCRC32            // load address of CRC
                MOV   R9D, dword ptr [RCX]        // move old CRC into R9D

                LEA   R10, qword [RIP + CRCTable] // address of CRCTable into R10

                CMP   R8, 0                       // check whether size is zero...
                JZ    @RoutineEnd                 // ...end calculation when it is

//-- Main calculation, loop executed RCX times ---------------------------------

                NOT   R9D

  @MainLoop:    MOV   AL,  byte ptr [RDX]
                XOR   AL,  R9B
                AND   RAX, $00000000000000FF

                MOV   EAX, dword ptr [R10 + RAX * 4]

                SHR   R9D, 8
                XOR   R9D, EAX
                INC   RDX

                DEC   R8
                JNZ   @MainLoop

                NOT   R9D

//-- Routine end ---------------------------------------------------------------                

  @RoutineEnd:  MOV   dword ptr [RCX], R9D        // store result

{$ELSE Windows}
{-------------------------------------------------------------------------------
  x86-64 assembly (64bit) - Linux

  Content of registers on enter:

    RDI   Self
    RSI   pointer to Buffer
    RDX   Size

  Used registers:
    RAX, RDX, RDI, RSI, R8, R9
-------------------------------------------------------------------------------}

                LEA   RDI, Self.fCRC32            // load address of CRC
                MOV   R8D, dword ptr [RDI]        // move old CRC into R8D

                LEA   R9, qword [RIP + CRCTable]  // address of CRCTable into R9

                CMP   RDX, 0                      // check whether size is zero...
                JZ    @RoutineEnd                 // ...end calculation when it is

//-- Main calculation, loop executed RCX times ---------------------------------

                NOT   R8D

  @MainLoop:    MOV   AL,  byte ptr [RSI]
                XOR   AL,  R8B
                AND   RAX, $00000000000000FF

                MOV   EAX, dword ptr [R9 + RAX * 4]

                SHR   R8D, 8
                XOR   R8D, EAX
                INC   RSI

                DEC   RDX
                JNZ   @MainLoop

                NOT   R8D

//-- Routine end ---------------------------------------------------------------

  @RoutineEnd:  MOV   dword ptr [RDI], R8D        // store result

{$ENDIF Windows}
{$ELSE x64}
{-------------------------------------------------------------------------------
  x86 assembly (32bit) - Windows, Linux

  Content of registers on enter:

    EAX   Self
    EDX   pointer to Buffer
    ECX   Size

  Used registers:
    EAX, EBX (value preserved), ECX, EDX
-------------------------------------------------------------------------------}

                LEA   EAX, Self.fCRC32      // load address of CRC
                PUSH  EAX                   // preserve address of CRC on stack
                MOV   EAX, dword ptr [EAX]  // move old CRC into EAX

                CMP   ECX, 0                // check whether size is zero...
                JZ    @RoutineEnd           // ...end calculation when it is

                PUSH  EBX                   // preserve EBX on stack
                MOV   EBX, EDX              // move @Buffer to EBX

//-- Main calculation, loop executed ECX times ---------------------------------

                NOT   EAX

  @MainLoop:    MOV   DL,  byte ptr [EBX]
                XOR   DL,  AL
                AND   EDX, $000000FF
                MOV   EDX, dword ptr [EDX * 4 + CRCTable]
                SHR   EAX, 8
                XOR   EAX, EDX
                INC   EBX

                DEC   ECX
                JNZ   @MainLoop

                NOT   EAX

//-- Routine end ---------------------------------------------------------------

                POP   EBX                   // restore EBX register

  @RoutineEnd:  POP   EDX                   // get address of CRC from stack
                MOV   dword ptr [EDX], EAX  // store result

{$ENDIF x64}
end;
{$ENDIF PurePascal}

//------------------------------------------------------------------------------

procedure TCRC32Hash.ProcessBuffer_PAS(const Buffer; Size: TMemSize);
var
  i:    TMemSize;
  Buff: PByte;
begin
fCRC32 := not fCRC32;
Buff := @Buffer;
For i := 1 to Size do
  begin
    fCRC32 := CRCTable[Byte(fCRC32 xor TCRC32Sys(Buff^))] xor (fCRC32 shr 8);
    Inc(Buff);
  end;
fCRC32 := not fCRC32;
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.ProcessBuffer(const Buffer; Size: TMemSize);
begin
fProcessBuffer(Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.Initialize;
begin
inherited;
fCRC32 := 0;
HashImplementation := himAssembly;  // sets fProcessBuffer
end;

{-------------------------------------------------------------------------------
    TCRC32Hash - public methods
-------------------------------------------------------------------------------}

class Function TCRC32Hash.CRC32ToSys(CRC32: TCRC32): TCRC32Sys;
begin
Result := {$IFNDEF ENDIAN_BIG}SwapEndian{$ENDIF}(TCRC32Sys(CRC32));
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.CRC32FromSys(CRC32: TCRC32Sys): TCRC32;
begin
Result := TCRC32({$IFNDEF ENDIAN_BIG}SwapEndian{$ENDIF}(CRC32));
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.CRC32ToLE(CRC32: TCRC32): TCRC32;
begin
Result := TCRC32(SwapEndian(TCRC32Sys(CRC32)));
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.CRC32ToBE(CRC32: TCRC32): TCRC32;
begin
Result := CRC32;
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.CRC32FromLE(CRC32: TCRC32): TCRC32;
begin
Result := TCRC32(SwapEndian(TCRC32Sys(CRC32)));
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.CRC32FromBE(CRC32: TCRC32): TCRC32;
begin
Result := CRC32;
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.HashSize: TMemSize;
begin
Result := SizeOf(TCRC32);
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.HashName: String;
begin
Result := 'CRC32';
end;

//------------------------------------------------------------------------------

class Function TCRC32Hash.HashEndianness: THashEndianness;
begin
Result := heBig;
end;

//------------------------------------------------------------------------------

constructor TCRC32Hash.CreateAndInitFrom(Hash: THashBase);
begin
CreateAndInit;
If Hash is TCRC32Hash then
  fCRC32 := TCRC32Hash(Hash).CRC32Sys
else
  raise ECRC32IncompatibleClass.CreateFmt('TCRC32Hash.ProcessBuffer: Incompatible class (%s).',[Hash.ClassName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

constructor TCRC32Hash.CreateAndInitFrom(Hash: TCRC32);
begin
CreateAndInit;
fCRC32 := CRC32ToSys(Hash);
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.Init;
begin
fCRC32 := CRC32ToSys(InitialCRC32);
end;

//------------------------------------------------------------------------------

Function TCRC32Hash.Compare(Hash: THashBase): Integer;
begin
If Hash is TCRC32Hash then
  begin
    If fCRC32 > TCRC32Hash(Hash).CRC32Sys then
      Result := +1
    else If fCRC32 < TCRC32Hash(Hash).CRC32Sys then
      Result := -1
    else
      Result := 0;
  end
else raise ECRC32IncompatibleClass.CreateFmt('TCRC32Hash.Compare: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

Function TCRC32Hash.AsString: String;
begin
Result := IntToHex(fCRC32,8);
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.FromString(const Str: String);
begin
If Length(Str) > 0 then
  begin
    If Str[1] = '$' then
      fCRC32 := TCRC32Sys(StrToInt(Str))
    else
      fCRC32 := TCRC32Sys(StrToInt('$' + Str));
  end
else fCRC32 := CRC32ToSys(InitialCRC32);
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.FromStringDef(const Str: String; const Default: TCRC32);
begin
If not TryFromString(Str) then
  fCRC32 := CRC32ToSys(Default);
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.SaveToStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TCRC32;
begin
case Endianness of
  heSystem: Temp := {$IFDEF ENDIAN_BIG}CRC32ToBE{$ELSE}CRC32ToLE{$ENDIF}(CRC32FromSys(fCRC32));
  heLittle: Temp := CRC32ToLE(CRC32FromSys(fCRC32));
  heBig:    Temp := CRC32ToBE(CRC32FromSys(fCRC32));
else
 {heDefault}
  Temp := CRC32FromSys(fCRC32);
end;
Stream.WriteBuffer(Temp,SizeOf(TCRC32));
end;

//------------------------------------------------------------------------------

{$IFDEF FPCDWM}{$PUSH}W5057{$ENDIF}
procedure TCRC32Hash.LoadFromStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TCRC32;
begin
Stream.ReadBuffer(Temp,SizeOf(TCRC32));
case Endianness of
  heSystem: fCRC32 := CRC32ToSys({$IFDEF ENDIAN_BIG}CRC32FromBE{$ELSE}CRC32FromLE{$ENDIF}(Temp));
  heLittle: fCRC32 := CRC32ToSys(CRC32FromLE(Temp));
  heBig:    fCRC32 := CRC32ToSys(CRC32FromBE(Temp));
else
 {heDefault}
  fCRC32 := CRC32ToSys(Temp);
end;
end;
{$IFDEF FPCDWM}{$POP}{$ENDIF}

{===============================================================================
    Backward compatibility functions
===============================================================================}
{-------------------------------------------------------------------------------
    Backward compatibility functions - utility functions
-------------------------------------------------------------------------------}

Function CRC32ToStr(CRC32: TCRC32): String;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.CreateAndInitFrom(CRC32);
try
  Result := Hash.AsString;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function StrToCRC32(const Str: String): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.FromString(Str);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function TryStrToCRC32(const Str: String; out CRC32: TCRC32): Boolean;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Result := Hash.TryFromString(Str);
  If Result then
    CRC32 := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function StrToCRC32Def(const Str: String; Default: TCRC32): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.FromStringDef(Str,Default);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function CompareCRC32(A,B: TCRC32): Integer;
var
  HashA:  TCRC32Hash;
  HashB:  TCRC32Hash;
begin
HashA := TCRC32Hash.CreateAndInitFrom(A);
try
  HashB := TCRC32Hash.CreateAndInitFrom(B);
  try
    Result := HashA.Compare(HashB);
  finally
    HashB.Free;
  end;
finally
  HashA.Free;
end;
end;

//------------------------------------------------------------------------------

Function SameCRC32(A,B: TCRC32): Boolean;
var
  HashA:  TCRC32Hash;
  HashB:  TCRC32Hash;
begin
HashA := TCRC32Hash.CreateAndInitFrom(A);
try
  HashB := TCRC32Hash.CreateAndInitFrom(B);
  try
    Result := HashA.Same(HashB);
  finally
    HashB.Free;
  end;
finally
  HashA.Free;
end;
end;

{-------------------------------------------------------------------------------
    Backward compatibility functions - processing functions
-------------------------------------------------------------------------------}

Function BufferCRC32(CRC32: TCRC32; const Buffer; Size: TMemSize): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.CreateAndInitFrom(CRC32);
try
  Hash.Final(Buffer,Size);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function BufferCRC32(const Buffer; Size: TMemSize): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashBuffer(Buffer,Size);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function AnsiStringCRC32(const Str: AnsiString): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashAnsiString(Str);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function WideStringCRC32(const Str: WideString): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashWideString(Str);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function StringCRC32(const Str: String): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashString(Str);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function StreamCRC32(Stream: TStream; Count: Int64 = -1): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashStream(Stream,Count);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

//------------------------------------------------------------------------------

Function FileCRC32(const FileName: String): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashFile(FileName);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

{-------------------------------------------------------------------------------
    Backward compatibility functions - context functions
-------------------------------------------------------------------------------}

Function CRC32_Init: TCRC32Context;
var
  Temp: TCRC32Hash;
begin
Temp := TCRC32Hash.CreateAndInit;
Result := TCRC32Context(Temp);
end;

//------------------------------------------------------------------------------

procedure CRC32_Update(Context: TCRC32Context; const Buffer; Size: TMemSize);
begin
TCRC32Hash(Context).Update(Buffer,Size);
end;

//------------------------------------------------------------------------------

Function CRC32_Final(var Context: TCRC32Context; const Buffer; Size: TMemSize): TCRC32;
begin
CRC32_Update(Context,Buffer,Size);
Result := CRC32_Final(Context);
end;

//------------------------------------------------------------------------------

Function CRC32_Final(var Context: TCRC32Context): TCRC32;
begin
TCRC32Hash(Context).Final;
Result := TCRC32Hash(Context).CRC32;
FreeAndNil(TCRC32Hash(Context));
end;

//------------------------------------------------------------------------------

Function CRC32_Hash(const Buffer; Size: TMemSize): TCRC32;
var
  Hash: TCRC32Hash;
begin
Hash := TCRC32Hash.Create;
try
  Hash.HashBuffer(Buffer,Size);
  Result := Hash.CRC32;
finally
  Hash.Free;
end;
end;

end.
