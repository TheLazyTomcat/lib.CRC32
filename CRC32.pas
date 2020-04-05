{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  CRC-32 calculation

    This unit provides classes that can be used to calculate CRC-32 value for
    any provided data (buffers, streams, strings, files, ...).

    Currently, it implements classes for "normal" CRC-32 (TCRC32Hash; the one
    used for example in ZIP, polynomial 0x104C11DB7) and CRC-32C (TCRC32CHash;
    Castagnoli, polynomial 0x11EDC6F41).
    There is also a class for custom calculation that offers an option to set
    arbitrary polynomial, intial value and select whether preinversion or
    postinversion is performed. Several polynomials beyond the already mentioned
    ones are also provided as public constants. These can be used with custom
    class to calculate different CRCs.

    For the sake of backward compatibility, there is a set of standalone
    functions that can be used. These functions are implemented abowe TCRC32Hash
    class and therefore are calculating CRC with a polynomial of 0x104C11DB7.

    WARNING - CRC-32C was not yet properly tested.

  Version 1.6 beta (2020-04-05)

  Last change 2020-04-05

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
    AuxClasses         - github.com/TheLazyTomcat/Lib.AuxClasses
    HashBase           - github.com/TheLazyTomcat/Lib.HashBase
    StrRect            - github.com/TheLazyTomcat/Lib.StrRect
    StaticMemoryStream - github.com/TheLazyTomcat/Lib.StaticMemoryStream
  * SimpleCPUID        - github.com/TheLazyTomcat/Lib.SimpleCPUID

    SimpleCPUID is required only when neither PurePascal nor CRC32_PurePascal
    symbol is defined and symbol CRC32C_Accelerated is defined.

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

{
  CRC32C_Accelerated

  When defined, and when symbol PurePascal is not defined, the CRC-32C (class
  TCRC32CHash) is compiled with an ability of using hardware-accelerated
  calculations via CRC32 instruction (part of SSE4.2 instruction set extension).

  Defined by default.
}
{$DEFINE CRC32C_Accelerated}

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

  TCRC32Table = array[Byte] of TCRC32Sys;
  PCRC32Table = ^TCRC32Table;

const
{
  Usual initial value for CRC-32.
  Can be different for some implementations.
}
  CRC32_INITVALUE:  TCRC32 = ($00,$00,$00,$00);

{
  Polynomials for common CRC-32 implementations.

  CRC32*_POLY are in original bit order with highest bit(1) omitted.

  CRC32*_POLYREF are with reflected (reversed) bit order and highest bit omitted.

  Full original polynomials are also provided for completeness.

  Source: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
}
  CRC32_POLY:   TCRC32Sys = $04C11DB7;  CRC32_POLYREF:   TCRC32Sys = $EDB88320;   {0x104C11DB7}
  CRC32C_POLY:  TCRC32Sys = $1EDC6F41;  CRC32C_POLYREF:  TCRC32Sys = $82F63B78;   {0x11EDC6F41}
  CRC32Q_POLY:  TCRC32Sys = $814141AB;  CRC32Q_POLYREF:  TCRC32Sys = $D5828281;   {0x1814141AB}
  CRC32K_POLY:  TCRC32Sys = $741B8CD7;  CRC32K_POLYREF:  TCRC32Sys = $EB31D82E;   {0x1741B8CD7}
  CRC32K2_POLY: TCRC32Sys = $32583499;  CRC32K2_POLYREF: TCRC32Sys = $992C1A4C;   {0x132583499}

type
  ECRC32Exception = class(EHashException);

  ECRC32IncompatibleClass = class(ECRC32Exception);

{-------------------------------------------------------------------------------
================================================================================
                                 TCRC32BaseHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32BaseHash - class declaration
===============================================================================}
type
  TCRC32BaseHash = class(TStreamHash)
  protected
    fCRC32Value:  TCRC32Sys;
    fCRC32Table:  PCRC32Table;
    fProcessBuffer: procedure(const Buffer; Size: TMemSize) of object; register;
    Function GetCRC32: TCRC32;
    Function GetCRC32Poly: TCRC32Sys; virtual;
    Function GetCRC32PolyRef: TCRC32Sys; virtual; abstract;
    Function GetHashImplementation: THashImplementation; override;
    procedure SetHashImplementation(Value: THashImplementation); override;
  {$IFNDEF PurePascal}
    procedure ProcessBuffer_ASM(const Buffer; Size: TMemSize); virtual; register;
  {$ENDIF}
    procedure ProcessBuffer_PAS(const Buffer; Size: TMemSize); virtual; register;
    procedure ProcessBuffer(const Buffer; Size: TMemSize); override;
    procedure Initialize; override;
    procedure Finalize; override;
    procedure InitializeTable; virtual; abstract;
    procedure FinalizeTable; virtual; abstract;
  public
    class Function CRC32ToSys(CRC32: TCRC32): TCRC32Sys; virtual;
    class Function CRC32FromSys(CRC32: TCRC32Sys): TCRC32; virtual;
    class Function CRC32ToLE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32ToBE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32FromLE(CRC32: TCRC32): TCRC32; virtual;
    class Function CRC32FromBE(CRC32: TCRC32): TCRC32; virtual;
    class Function HashSize: TMemSize; override;
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
    property CRC32Sys: TCRC32Sys read fCRC32Value;
    property CRC32Poly: TCRC32Sys read GetCRC32Poly;        // polynomial
    property CRC32PolyRef: TCRC32Sys read GetCRC32PolyRef;  // polynomial with reflected bit order
    property CRC32Table: PCRC32Table read fCRC32Table;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32Hash - class declaration
===============================================================================}
type
  TCRC32Hash = class(TCRC32BaseHash)
  protected
    Function GetCRC32PolyRef: TCRC32Sys; override;
    procedure InitializeTable; override;
    procedure FinalizeTable; override;
  public
    class Function HashName: String; override;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32CHash                                  
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32CHash - class declaration
===============================================================================}
type
  TCRC32CHash = class(TCRC32BaseHash)
  protected
    Function AccelerationSupported: Boolean; virtual;
    Function GetCRC32PolyRef: TCRC32Sys; override;
    Function GetHashImplementation: THashImplementation; override;
    procedure SetHashImplementation(Value: THashImplementation); override;
  {$IF not defined(PurePascal) and defined(CRC32C_Accelerated)}
    procedure ProcessBuffer_ACC(const Buffer; Size: TMemSize); virtual; register;
  {$IFEND}
    procedure InitializeTable; override;
    procedure FinalizeTable; override;
  public
    class Function HashName: String; override;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                TCRC32CustomHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32CustomHash - class declaration
===============================================================================}
type
  TCRC32CustomHash = class(TCRC32BaseHash)
  protected
    fCRC32Poly:     TCRC32Sys;
    fCRC32Initial:  TCRC32;
    fPreInversion:  Boolean;
    fPostInversion: Boolean;
    procedure SetCRC32Poly(Value: TCRC32Sys); virtual;
    Function GetCRC32PolyRef: TCRC32Sys; override;
    procedure SetCRC32PolyRef(Value: TCRC32Sys); virtual;
    procedure ProcessBuffer(const Buffer; Size: TMemSize); override;
    procedure BuildTable; virtual;
    procedure Initialize; override;
    procedure InitializeTable; override;
    procedure FinalizeTable; override;
  public
    class Function HashName: String; override;
    procedure Init; override;
    property CRC32Poly: TCRC32Sys read GetCRC32Poly write SetCRC32Poly;
    property CRC32PolyRef: TCRC32Sys read GetCRC32PolyRef write SetCRC32PolyRef;
    property CRC32InitialValue: TCRC32 read fCRC32Initial write fCRC32Initial;
    property PreInversion: Boolean read fPreInversion write fPreInversion;
    property PostInversion: Boolean read fPostInversion write fPostInversion;
  end;

{===============================================================================
    Backward compatibility functions
===============================================================================}
{
  All following functions are implemented as simple wrappers for TCRC32Hash
  class and its methods.
}

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
  SysUtils
{$IF not defined(PurePascal) and defined(CRC32C_Accelerated)}
  , SimpleCPUID
{$IFEND};

{$IFDEF FPC_DisableWarns}
  {$DEFINE FPCDWM}
  {$DEFINE W5057:={$WARN 5057 OFF}} // Local variable "$1" does not seem to be initialized
{$ENDIF}

{$IF not Defined(FPC) and not Defined(x64)}
  {
    ASM_MachineCode

    When defined, some ASM instructions are inserted into byte stream directly
    as a machine code. It is there because not all compilers supports, and
    therefore can compile, such instructions.
    As I am not able to tell which 32bit delphi compilers do support them,
    I am assuming none of them do. I am also assuming that all 64bit delphi
    compilers and current FPCs are supporting the instructions.
    Has no effect when PurePascal is defined.
  }
  {$DEFINE ASM_MachineCode}
{$IFEND}


{-------------------------------------------------------------------------------
================================================================================
                                 TCRC32BaseHash
================================================================================
-------------------------------------------------------------------------------}

{===============================================================================
    TCRC32BaseHash - Utility functions
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

//------------------------------------------------------------------------------

Function ReverseBits(Value: TCRC32Sys): TCRC32Sys;
var
  i:  Integer;
begin
Result := 0;
For i := 0 to 31 do
  Result := Result or (((Value shr i) and 1) shl (31 - i));
end;

{===============================================================================
    TCRC32BaseHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TCRC32BaseHash - protected methods
-------------------------------------------------------------------------------}

Function TCRC32BaseHash.GetCRC32: TCRC32;
begin
Result := CRC32FromSys(fCRC32Value);
end;

//------------------------------------------------------------------------------

Function TCRC32BaseHash.GetCRC32Poly: TCRC32Sys;
begin
Result := ReverseBits(GetCRC32PolyRef);
end;

//------------------------------------------------------------------------------

Function TCRC32BaseHash.GetHashImplementation: THashImplementation;
begin
{$IFNDEF PurePascal}
If TMethod(fProcessBuffer).Code = @TCRC32Hash.ProcessBuffer_ASM then
  Result := himAssembly
else
{$ENDIF}
  Result := himPascal; 
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.SetHashImplementation(Value: THashImplementation);
begin
case Value of
  himAssembly,
  himAccelerated: {$IFDEF PurePascal}
                    fProcessBuffer := ProcessBuffer_PAS;
                  {$ELSE}
                    fProcessBuffer := ProcessBuffer_ASM;
                  {$ENDIF}
else
 {himPascal}
  fProcessBuffer := ProcessBuffer_PAS;
end;
end;

//------------------------------------------------------------------------------

{$IFNDEF PurePascal}
procedure TCRC32BaseHash.ProcessBuffer_ASM(const Buffer; Size: TMemSize); assembler;
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

                MOV   R10, qword ptr Self.fCRC32Table // address of CRC table into R10
                LEA   RCX, Self.fCRC32Value           // load address of CRC
                MOV   R9D, dword ptr [RCX]            // move old CRC into R9D

                TEST  R8, R8                          // check whether size is zero...
                JZ    @RoutineEnd                     // ...end calculation when it is

//-- Main calculation, loop executed RCX times ---------------------------------

  @MainLoop:    MOV   AL,  byte ptr [RDX]
                XOR   AL,  R9B
                AND   RAX, $00000000000000FF
                MOV   EAX, dword ptr [R10 + RAX * 4]
                SHR   R9D, 8
                XOR   R9D, EAX
                INC   RDX

                DEC   R8
                JNZ   @MainLoop

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

                MOV   R9, qword ptr Self.fCRC32Table  // address of CRC table into R9
                LEA   RDI, Self.fCRC32Value           // load address of CRC
                MOV   R8D, dword ptr [RDI]            // move old CRC into R8D

                TEST  RDX, RDX                        // check whether size is zero...
                JZ    @RoutineEnd                     // ...end calculation when it is

//-- Main calculation, loop executed RCX times ---------------------------------

  @MainLoop:    MOV   AL,  byte ptr [RSI]
                XOR   AL,  R8B
                AND   RAX, $00000000000000FF
                MOV   EAX, dword ptr [R9 + RAX * 4]
                SHR   R8D, 8
                XOR   R8D, EAX
                INC   RSI

                DEC   RDX
                JNZ   @MainLoop

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
    EAX, EBX (value preserved), ECX, EDX, ESI (value preserved)
-------------------------------------------------------------------------------}

                PUSH  ESI                               // preserve ESI on stack
                MOV   ESI, dword ptr Self.fCRC32Table   // address of CRC table into ESI

                LEA   EAX, Self.fCRC32Value             // load address of CRC
                PUSH  EAX                               // preserve address of CRC on stack
                MOV   EAX, dword ptr [EAX]              // move old CRC into EAX

                TEST  ECX, ECX                          // check whether size is zero...
                JZ    @RoutineEnd                       // ...end calculation when it is

                PUSH  EBX                               // preserve EBX on stack
                MOV   EBX, EDX                          // move @Buffer to EBX

//-- Main calculation, loop executed ECX times ---------------------------------

  @MainLoop:    MOV   DL,  byte ptr [EBX]
                XOR   DL,  AL
                AND   EDX, $000000FF
                MOV   EDX, dword ptr [ESI + EDX * 4]
                SHR   EAX, 8
                XOR   EAX, EDX
                INC   EBX

                DEC   ECX
                JNZ   @MainLoop

//-- Routine end ---------------------------------------------------------------

                POP   EBX                   // restore EBX register

  @RoutineEnd:  POP   EDX                   // get address of CRC from stack
                MOV   dword ptr [EDX], EAX  // store result

                POP   ESI                   // restore ESI register

{$ENDIF x64}
end;
{$ENDIF PurePascal}

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.ProcessBuffer_PAS(const Buffer; Size: TMemSize);
var
  i:    TMemSize;
  Buff: PByte;
begin
Buff := @Buffer;
For i := 1 to Size do
  begin
    fCRC32Value := fCRC32Table^[Byte(fCRC32Value xor TCRC32Sys(Buff^))] xor (fCRC32Value shr 8);
    Inc(Buff);
  end;
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.ProcessBuffer(const Buffer; Size: TMemSize);
begin
fCRC32Value := not fCRC32Value;
fProcessBuffer(Buffer,Size);
fCRC32Value := not fCRC32Value;
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.Initialize;
begin
inherited;
fCRC32Value := 0;
InitializeTable;
HashImplementation := himAccelerated;  // sets fProcessBuffer
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.Finalize;
begin
FinalizeTable;
inherited;
end;

{-------------------------------------------------------------------------------
    TCRC32BaseHash - public methods
-------------------------------------------------------------------------------}

class Function TCRC32BaseHash.CRC32ToSys(CRC32: TCRC32): TCRC32Sys;
begin
Result := {$IFNDEF ENDIAN_BIG}SwapEndian{$ENDIF}(TCRC32Sys(CRC32));
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.CRC32FromSys(CRC32: TCRC32Sys): TCRC32;
begin
Result := TCRC32({$IFNDEF ENDIAN_BIG}SwapEndian{$ENDIF}(CRC32));
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.CRC32ToLE(CRC32: TCRC32): TCRC32;
begin
Result := TCRC32(SwapEndian(TCRC32Sys(CRC32)));
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.CRC32ToBE(CRC32: TCRC32): TCRC32;
begin
Result := CRC32;
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.CRC32FromLE(CRC32: TCRC32): TCRC32;
begin
Result := TCRC32(SwapEndian(TCRC32Sys(CRC32)));
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.CRC32FromBE(CRC32: TCRC32): TCRC32;
begin
Result := CRC32;
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.HashSize: TMemSize;
begin
Result := SizeOf(TCRC32);
end;

//------------------------------------------------------------------------------

class Function TCRC32BaseHash.HashEndianness: THashEndianness;
begin
Result := heBig;
end;

//------------------------------------------------------------------------------

constructor TCRC32BaseHash.CreateAndInitFrom(Hash: THashBase);
begin
CreateAndInit;
If Hash is TCRC32Hash then
  fCRC32Value := TCRC32Hash(Hash).CRC32Sys
else
  raise ECRC32IncompatibleClass.CreateFmt('TCRC32Hash.ProcessBuffer: Incompatible class (%s).',[Hash.ClassName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

constructor TCRC32BaseHash.CreateAndInitFrom(Hash: TCRC32);
begin
CreateAndInit;
fCRC32Value := CRC32ToSys(Hash);
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.Init;
begin
fCRC32Value := CRC32ToSys(CRC32_INITVALUE);
end;

//------------------------------------------------------------------------------

Function TCRC32BaseHash.Compare(Hash: THashBase): Integer;
begin
If Hash is TCRC32Hash then
  begin
    If fCRC32Value > TCRC32Hash(Hash).CRC32Sys then
      Result := +1
    else If fCRC32Value < TCRC32Hash(Hash).CRC32Sys then
      Result := -1
    else
      Result := 0;
  end
else raise ECRC32IncompatibleClass.CreateFmt('TCRC32Hash.Compare: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

Function TCRC32BaseHash.AsString: String;
begin
Result := IntToHex(fCRC32Value,8);
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.FromString(const Str: String);
begin
If Length(Str) > 0 then
  begin
    If Str[1] = '$' then
      fCRC32Value := TCRC32Sys(StrToInt(Str))
    else
      fCRC32Value := TCRC32Sys(StrToInt('$' + Str));
  end
else fCRC32Value := CRC32ToSys(CRC32_INITVALUE);
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.FromStringDef(const Str: String; const Default: TCRC32);
begin
If not TryFromString(Str) then
  fCRC32Value := CRC32ToSys(Default);
end;

//------------------------------------------------------------------------------

procedure TCRC32BaseHash.SaveToStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TCRC32;
begin
case Endianness of
  heSystem: Temp := {$IFDEF ENDIAN_BIG}CRC32ToBE{$ELSE}CRC32ToLE{$ENDIF}(CRC32FromSys(fCRC32Value));
  heLittle: Temp := CRC32ToLE(CRC32FromSys(fCRC32Value));
  heBig:    Temp := CRC32ToBE(CRC32FromSys(fCRC32Value));
else
 {heDefault}
  Temp := CRC32FromSys(fCRC32Value);
end;
Stream.WriteBuffer(Temp,SizeOf(TCRC32));
end;

//------------------------------------------------------------------------------

{$IFDEF FPCDWM}{$PUSH}W5057{$ENDIF}
procedure TCRC32BaseHash.LoadFromStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TCRC32;
begin
Stream.ReadBuffer(Temp,SizeOf(TCRC32));
case Endianness of
  heSystem: fCRC32Value := CRC32ToSys({$IFDEF ENDIAN_BIG}CRC32FromBE{$ELSE}CRC32FromLE{$ENDIF}(Temp));
  heLittle: fCRC32Value := CRC32ToSys(CRC32FromLE(Temp));
  heBig:    fCRC32Value := CRC32ToSys(CRC32FromBE(Temp));
else
 {heDefault}
  fCRC32Value := CRC32ToSys(Temp);
end;
end;
{$IFDEF FPCDWM}{$POP}{$ENDIF}

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32Hash - calculation constants
===============================================================================}

const
  CRC32_TABLE: TCRC32Table = (
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
    TCRC32Hash - protected methods
-------------------------------------------------------------------------------}

Function TCRC32Hash.GetCRC32PolyRef: TCRC32Sys;
begin
Result := CRC32_POLYREF;
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.InitializeTable;
begin
fCRC32Table := @CRC32_TABLE;
end;

//------------------------------------------------------------------------------

procedure TCRC32Hash.FinalizeTable;
begin
fCRC32Table := nil;
end;

{-------------------------------------------------------------------------------
    TCRC32Hash - public methods
-------------------------------------------------------------------------------}

class Function TCRC32Hash.HashName: String;
begin
Result := 'CRC-32';
end;

{-------------------------------------------------------------------------------
================================================================================
                                   TCRC32CHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32CHash - calculation constants
===============================================================================}

const
  CRC32C_TABLE: TCRC32Table = (
    $00000000, $F26B8303, $E13B70F7, $1350F3F4, $C79A971F, $35F1141C, $26A1E7E8, $D4CA64EB,
    $8AD958CF, $78B2DBCC, $6BE22838, $9989AB3B, $4D43CFD0, $BF284CD3, $AC78BF27, $5E133C24,
    $105EC76F, $E235446C, $F165B798, $030E349B, $D7C45070, $25AFD373, $36FF2087, $C494A384,
    $9A879FA0, $68EC1CA3, $7BBCEF57, $89D76C54, $5D1D08BF, $AF768BBC, $BC267848, $4E4DFB4B,
    $20BD8EDE, $D2D60DDD, $C186FE29, $33ED7D2A, $E72719C1, $154C9AC2, $061C6936, $F477EA35,
    $AA64D611, $580F5512, $4B5FA6E6, $B93425E5, $6DFE410E, $9F95C20D, $8CC531F9, $7EAEB2FA,
    $30E349B1, $C288CAB2, $D1D83946, $23B3BA45, $F779DEAE, $05125DAD, $1642AE59, $E4292D5A,
    $BA3A117E, $4851927D, $5B016189, $A96AE28A, $7DA08661, $8FCB0562, $9C9BF696, $6EF07595,
    $417B1DBC, $B3109EBF, $A0406D4B, $522BEE48, $86E18AA3, $748A09A0, $67DAFA54, $95B17957,
    $CBA24573, $39C9C670, $2A993584, $D8F2B687, $0C38D26C, $FE53516F, $ED03A29B, $1F682198,
    $5125DAD3, $A34E59D0, $B01EAA24, $42752927, $96BF4DCC, $64D4CECF, $77843D3B, $85EFBE38,
    $DBFC821C, $2997011F, $3AC7F2EB, $C8AC71E8, $1C661503, $EE0D9600, $FD5D65F4, $0F36E6F7,
    $61C69362, $93AD1061, $80FDE395, $72966096, $A65C047D, $5437877E, $4767748A, $B50CF789,
    $EB1FCBAD, $197448AE, $0A24BB5A, $F84F3859, $2C855CB2, $DEEEDFB1, $CDBE2C45, $3FD5AF46,
    $7198540D, $83F3D70E, $90A324FA, $62C8A7F9, $B602C312, $44694011, $5739B3E5, $A55230E6,
    $FB410CC2, $092A8FC1, $1A7A7C35, $E811FF36, $3CDB9BDD, $CEB018DE, $DDE0EB2A, $2F8B6829,
    $82F63B78, $709DB87B, $63CD4B8F, $91A6C88C, $456CAC67, $B7072F64, $A457DC90, $563C5F93,
    $082F63B7, $FA44E0B4, $E9141340, $1B7F9043, $CFB5F4A8, $3DDE77AB, $2E8E845F, $DCE5075C,
    $92A8FC17, $60C37F14, $73938CE0, $81F80FE3, $55326B08, $A759E80B, $B4091BFF, $466298FC,
    $1871A4D8, $EA1A27DB, $F94AD42F, $0B21572C, $DFEB33C7, $2D80B0C4, $3ED04330, $CCBBC033,
    $A24BB5A6, $502036A5, $4370C551, $B11B4652, $65D122B9, $97BAA1BA, $84EA524E, $7681D14D,
    $2892ED69, $DAF96E6A, $C9A99D9E, $3BC21E9D, $EF087A76, $1D63F975, $0E330A81, $FC588982,
    $B21572C9, $407EF1CA, $532E023E, $A145813D, $758FE5D6, $87E466D5, $94B49521, $66DF1622,
    $38CC2A06, $CAA7A905, $D9F75AF1, $2B9CD9F2, $FF56BD19, $0D3D3E1A, $1E6DCDEE, $EC064EED,
    $C38D26C4, $31E6A5C7, $22B65633, $D0DDD530, $0417B1DB, $F67C32D8, $E52CC12C, $1747422F,
    $49547E0B, $BB3FFD08, $A86F0EFC, $5A048DFF, $8ECEE914, $7CA56A17, $6FF599E3, $9D9E1AE0,
    $D3D3E1AB, $21B862A8, $32E8915C, $C083125F, $144976B4, $E622F5B7, $F5720643, $07198540,
    $590AB964, $AB613A67, $B831C993, $4A5A4A90, $9E902E7B, $6CFBAD78, $7FAB5E8C, $8DC0DD8F,
    $E330A81A, $115B2B19, $020BD8ED, $F0605BEE, $24AA3F05, $D6C1BC06, $C5914FF2, $37FACCF1,
    $69E9F0D5, $9B8273D6, $88D28022, $7AB90321, $AE7367CA, $5C18E4C9, $4F48173D, $BD23943E,
    $F36E6F75, $0105EC76, $12551F82, $E03E9C81, $34F4F86A, $C69F7B69, $D5CF889D, $27A40B9E,
    $79B737BA, $8BDCB4B9, $988C474D, $6AE7C44E, $BE2DA0A5, $4C4623A6, $5F16D052, $AD7D5351);

{===============================================================================
    TCRC32CHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TCRC32CHash - protected methods
-------------------------------------------------------------------------------}

Function TCRC32CHash.AccelerationSupported: Boolean;
begin
{$IF not defined(PurePascal) and defined(CRC32C_Accelerated)}
with TSimpleCPUID.Create do
try
  Result := Info.SupportedExtensions.CRC32;
finally
  Free;
end;
{$ELSE}
Result := False;
{$IFEND}
end;

//------------------------------------------------------------------------------

Function TCRC32CHash.GetCRC32PolyRef: TCRC32Sys;
begin
Result := CRC32C_POLYREF;
end;

//------------------------------------------------------------------------------

Function TCRC32CHash.GetHashImplementation: THashImplementation;
begin
{$IFNDEF PurePascal}
{$IFDEF CRC32C_Accelerated}
If TMethod(fProcessBuffer).Code = @TCRC32CHash.ProcessBuffer_ACC then
  Result := himAccelerated
else
{$ENDIF}
If TMethod(fProcessBuffer).Code = @TCRC32CHash.ProcessBuffer_ASM then
  Result := himAssembly
else
{$ENDIF}
  Result := himPascal;
end;

//------------------------------------------------------------------------------

procedure TCRC32CHash.SetHashImplementation(Value: THashImplementation);
begin
case Value of
  himAssembly:    {$IFDEF PurePascal}
                    fProcessBuffer := ProcessBuffer_PAS;
                  {$ELSE}
                    fProcessBuffer := ProcessBuffer_ASM;
                  {$ENDIF}
  himAccelerated: {$IFDEF PurePascal}
                    fProcessBuffer := ProcessBuffer_PAS;
                  {$ELSE}
                  {$IFDEF CRC32C_Accelerated}
                    If AccelerationSupported then
                      fProcessBuffer := ProcessBuffer_ACC
                    else
                  {$ENDIF}
                      fProcessBuffer := ProcessBuffer_ASM;
                  {$ENDIF}
else
 {himPascal}
  fProcessBuffer := ProcessBuffer_PAS;
end;
end;

//------------------------------------------------------------------------------

{$IF not defined(PurePascal) and defined(CRC32C_Accelerated)}
{
  Note that following implementation expects relatively long buffers, so it is
  written with larger overhead but shorter calculation cycles.
}
procedure TCRC32CHash.ProcessBuffer_ACC(const Buffer; Size: TMemSize); assembler;
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
    RAX, RCX, RDX, R8
-------------------------------------------------------------------------------}

                LEA   RCX, Self.fCRC32Value   // load address of CRC

                TEST  R8, R8                  // check the size
                JZ    @RoutineEnd             // end calculation when it is zero

//-- Main calculation ----------------------------------------------------------

                MOV   EAX, dword ptr [RCX]    // load old crc value

                PUSH  R8
                SHR   R8, 3
                JZ    @ByteProc

  @QuadLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $48, $0F, $38, $F1, $02
              {$ELSE}
                CRC32 RAX, qword ptr [RDX]
              {$ENDIF}
                ADD   RDX, 8

                DEC   R8
                JNZ   @QuadLoop

  @ByteProc:    POP   R8
                AND   R8, 7
                JZ    @ProcDone

  @ByteLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $48, $0F, $38, $F0, $02
              {$ELSE}
                CRC32 RAX, byte ptr [RDX]
              {$ENDIF}
                INC   RDX

                DEC   R8
                JNZ   @ByteLoop

  @ProcDone:    MOV   dword ptr [RCX], EAX    // store resulting crc

//-- Routine end ---------------------------------------------------------------

  @RoutineEnd:

{$ELSE Windows}
{-------------------------------------------------------------------------------
  x86-64 assembly (64bit) - Linux

  Content of registers on enter:

    RDI   Self
    RSI   pointer to Buffer
    RDX   Size

  Used registers:
    RAX, RDX, RDI, RSI
-------------------------------------------------------------------------------}

                LEA   RDI, Self.fCRC32Value   // load address of CRC

                TEST  RDX, RDX                // check the size
                JZ    @RoutineEnd             // end calculation when it is zero

//-- Main calculation ----------------------------------------------------------

                MOV   EAX, dword ptr [RDI]    // load old crc value

                PUSH  RDX
                SHR   RDX, 3
                JZ    @ByteProc

  @QuadLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $48, $0F, $38, $F1, $06
              {$ELSE}
                CRC32 RAX, qword ptr [RSI]
              {$ENDIF}
                ADD   RSI, 8

                DEC   RDX
                JNZ   @QuadLoop

  @ByteProc:    POP   RDX
                AND   RDX, 7
                JZ    @ProcDone

  @ByteLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $48, $0F, $38, $F0, $06
              {$ELSE}
                CRC32 RAX, byte ptr [RSI]
              {$ENDIF}
                INC   RSI

                DEC   RDX
                JNZ   @ByteLoop

  @ProcDone:    MOV   dword ptr [RDI], EAX    // store resulting crc

//-- Routine end ---------------------------------------------------------------

  @RoutineEnd:

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

                PUSH  EBX                     // preserve EBX on stack

                LEA   EBX, Self.fCRC32Value   // load address of CRC

                TEST  ECX, ECX                // check the size
                JZ    @RoutineEnd             // end calculation when it is zero

//-- Main calculation ----------------------------------------------------------

                MOV   EAX, dword ptr [EBX]    // load old crc value

                PUSH  ECX
                SHR   ECX, 2
                JZ    @ByteProc

  @LongLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $0F, $38, $F1, $02
              {$ELSE}
                CRC32 EAX, dword ptr [EDX]
              {$ENDIF}
                ADD   EDX, 4

                DEC   ECX
                JNZ   @LongLoop

  @ByteProc:    POP   ECX
                AND   ECX, 3
                JZ    @ProcDone

  @ByteLoop:  {$IFDEF ASM_MachineCode}
                DB $F2, $0F, $38, $F0, $02
              {$ELSE}
                CRC32 EAX, byte ptr [EDX]
              {$ENDIF}
                INC   EDX

                DEC   ECX
                JNZ   @ByteLoop

  @ProcDone:    MOV   dword ptr [EBX], EAX    // store resulting crc

//-- Routine end ---------------------------------------------------------------

  @RoutineEnd:  POP   EBX                     // restore EBX register

{$ENDIF x64}
end;
{$IFEND}

//------------------------------------------------------------------------------

procedure TCRC32CHash.InitializeTable;
begin
fCRC32Table := @CRC32C_TABLE;
end;

//------------------------------------------------------------------------------

procedure TCRC32CHash.FinalizeTable;
begin
fCRC32Table := nil;
end;

{-------------------------------------------------------------------------------
    TCRC32Hash - public methods
-------------------------------------------------------------------------------}

class Function TCRC32CHash.HashName: String;
begin
Result := 'CRC-32C';
end;

{-------------------------------------------------------------------------------
================================================================================
                                TCRC32CustomHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TCRC32CustomHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TCRC32CustomHash - protected methods
-------------------------------------------------------------------------------}

procedure TCRC32CustomHash.SetCRC32Poly(Value: TCRC32Sys);
begin
SetCRC32PolyRef(ReverseBits(Value));
end;

//------------------------------------------------------------------------------

Function TCRC32CustomHash.GetCRC32PolyRef: TCRC32Sys;
begin
Result := fCRC32Poly;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.SetCRC32PolyRef(Value: TCRC32Sys);
begin
If fCRC32Poly <> Value then
  begin
    fCRC32Poly := Value;
    BuildTable;
  end;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.ProcessBuffer(const Buffer; Size: TMemSize);
begin
If fPreInversion then
  fCRC32Value := not fCRC32Value;
fProcessBuffer(Buffer,Size);
If fPostInversion then
  fCRC32Value := not fCRC32Value;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.BuildTable;
var
  i,j:  Integer;
  Temp: TCRC32Sys;
begin
For i := Low(TCRC32Table) to High(TCRC32Table) do
  begin
    Temp := TCRC32Sys(i) shl 1;
    For j := 8 downto 0 do
      begin
        If (Temp and 1) <> 0 then
          Temp := (Temp shr 1) xor fCRC32Poly
        else
          Temp := Temp shr 1;
      end;
    fCRC32Table^[i] := Temp;
  end;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.Initialize;
begin
fCRC32Poly := CRC32_POLYREF;
inherited;  // calls InitializeTable, so polynomial must be set before it
fCRC32Initial := CRC32_INITVALUE;
fPreInversion := True;
fPostInversion := True;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.InitializeTable;
begin
New(fCRC32Table);
BuildTable;
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.FinalizeTable;
begin
Dispose(fCRC32Table);
end;

{-------------------------------------------------------------------------------
    TCRC32CustomHash - public methods
-------------------------------------------------------------------------------}

class Function TCRC32CustomHash.HashName: String;
begin
Result := 'CRC-32(custom)';
end;

//------------------------------------------------------------------------------

procedure TCRC32CustomHash.Init;
begin
fCRC32Value := CRC32ToSys(fCRC32Initial);
end;

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
