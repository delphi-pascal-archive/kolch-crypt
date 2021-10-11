//***    KOLCHCRYPT - SIMPLY 512-BIT KEY 512-BIT BLOCK CBC-LIKE MODE HASHTRICK ENCRYPTION ALGORITHM       ***//

// Inludes some key and table mutation

// Written by Alexander Myasnikov, Kolchugino, Vladimir region, Russia

// July, 2008

// E-Mail: alexanderwdark@ya.ru

// Web: www.darksoftware.narod.ru

// Freeware, opensource, free for any usage, not patented

// This is only idea, working idea. There are some bugs? Code is slow and not optimized.



unit kolchcrypt;

interface

uses
  DCPsha512, DCPHaval,
  Windows, Messages, SysUtils, Variants, Classes;


type tprocessproc = procedure (done: integer);
type pprocessproc = ^tprocessproc;





function Kolch_Crypt (fi,ft: string; skey: string; dir: byte; process: pprocessproc=nil): boolean;


implementation


const NUMROUNDS=8;


type tkey= array  [0..63] of byte; // Key data

var cry_t: array [0..63] of byte; // Main encryption table

var hash_t: array [0..63] of byte; // Main encryption table

var cry_t_c: array [0..63] of byte; // Main encryption table copy

var cry_t1: array [0..31] of byte; // Temp enctable

var cry_t2: array [0..31] of byte; // Temp enctable

var p_tab: array [0..255] of byte; // Substtable for data mutation (encryption)

var p_dtab: array [0..255] of byte; // Substtable for data mutation (decryption)

var p_tab_t: array [0..255] of byte; // Substtable for data mutation (encryption)


function tab_ex(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p_tab[i]=data then begin
result:=true;
break;
end;
end;
end;


function xSucc(b,s: byte): byte;  // Rotate bytes
begin
if (b+s)>255  then begin
result:=(b+s)-255-1;
end else result:=b+s;
end;

function xPred(b,s: byte): byte;  // Rotate bytes
begin
if (b-s)<0  then begin
result:=256-s+b;
end else result:=b-s;
end;


procedure mutatetables(idx: integer); // Mutate table
var i,nv: integer;
var Hash: TDCP_SHA512;
begin

for i:=0 to 255 do begin
nv:=xsucc(p_tab[i],idx);
p_tab[i]:=nv;
p_dtab[nv]:=i;
end;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab,256);
fillchar(hash_t,64,0);
Hash.Final(hash_t);
Hash.Free;


end;

procedure mutatekey(var key: tkey; idx: integer); // Mutate key
var i: integer;
begin
for i:=0 to 63 do begin
key[i]:=xsucc(key[i],idx);
end;

end;


procedure mutatecryt(idx: integer); // Mutate crypt table
var i: integer;
begin
for i:=0 to 63 do begin
cry_t[i]:=xsucc(cry_t[i],idx);
end;

end;


procedure XORBuff(I1, I2: Pointer; Size: Integer; Dest: Pointer); assembler;  // Buffer xoring

asm
       AND   ECX,ECX
       JZ    @@5
       PUSH  ESI
       PUSH  EDI
       MOV   ESI,EAX
       MOV   EDI,Dest
@@1:   TEST  ECX,3
       JNZ   @@3
@@2:   SUB   ECX,4
       JL    @@4
       MOV   EAX,[ESI + ECX]
       XOR   EAX,[EDX + ECX]
       MOV   [EDI + ECX],EAX
       JMP   @@2
@@3:   DEC   ECX
       MOV   AL,[ESI + ECX]
       XOR   AL,[EDX + ECX]
       MOV   [EDI + ECX],AL
       JMP   @@1
@@4:   POP   EDI
       POP   ESI
@@5:
end;


procedure initPT(var key: tkey); // Generate substtable


var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: array [0..63] of byte; p_xortab: array [0..255] of byte; p_cttab: array [0..255] of byte;
var idx: integer; ctr, ct: byte;
begin
fillchar(p_tab,256,0);
fillchar(p_dtab,256,0);
fillchar(p_xortab,256,0);
fillchar(p_cttab,256,0);
idx:=0;
move(key,p_tab,64);
move(key,p_tab[64],64);
move(key,p_tab[128],64);
move(key,p_tab[192],64);

ctr:=0;
ct:=0;

ct:=key[0] xor key[63] xor key [13];

repeat


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab,256);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_dtab,256);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;

XorBuff(@p_tab,@p_dtab,256,@p_xortab);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab,256);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;

if ct<255 then inc(ct) else
begin
ct:=0;
mutatekey(key,ctr);
end;

ctr:= p_tab [ct] xor p_dtab[255-ct];

for i:=0 to 255 do begin
p_cttab[i]:=p_xortab[i] xor ctr;
end;


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab,256);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;



for i:=0 to 63 do begin

if not (tab_ex(rnd[i],idx)) then begin
p_tab[idx]:=rnd[i];
p_dtab[rnd[i]]:=idx;
inc(idx,1);
break;
end

else if not (tab_ex(rnd2[i],idx)) then begin
p_tab[idx]:=rnd2[i];
p_dtab[rnd2[i]]:=idx;
inc(idx,1);
break;
end

else

if not (tab_ex(rnd3[i],idx)) then begin
p_tab[idx]:=rnd3[i];
p_dtab[rnd3[i]]:=idx;
inc(idx,1);

break;
end

else

if not (tab_ex(rnd4[i],idx)) then begin
p_tab[idx]:=rnd4[i];
p_dtab[rnd4[i]]:=idx;
inc(idx,1);
break;
end;


end;



until (idx > 255);

mutatetables(key[0]);
end;



procedure initcipher(var key: tkey);  // Init xor table based on key hash

var Hash: TDCP_SHA512;i: integer; Hash2: TDCP_Haval;
begin
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key,64);
Hash.Final(cry_t);
Hash.Free;
for i:=0 to 63 do cry_t[i]:=cry_t[i] xor key[i];

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(cry_t,32);
Hash2.Final(cry_t1);
Hash2.Free;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(cry_t[32],32);
Hash2.Final(cry_t2);
Hash2.Free;

for i:=0 to 31 do begin
cry_t[i]:=cry_t[i] xor cry_t1[i];
cry_t[i+32]:=cry_t[i+32] xor cry_t2[i];
end;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(cry_t,64);
Hash.Final(key);
Hash.Free;

for i:=0 to 63 do begin
case key[i] of
100..155:  begin
cry_t[i]:=cry_t[63-i] xor key[63-i];
end;

0..99: begin
cry_t[i]:=cry_t[63-i] xor not (key[63-i]);

end;

156..255: begin
cry_t[i]:=cry_t[63-i] xor not (cry_t[i]);

end;


end;

end;

mutatecryt(key[32]);
end;



procedure CryptBlock (buf: pointer;const size: integer;dir: byte);  // Main block encryption round, use dir=1 for decryption
var i: integer;
begin


for i:=0 to size-1 do begin


if dir=0  then pbytearray(buf)[i]:=xpred(pbytearray(buf)[i],hash_t[i]);


if dir=1 then pbytearray(buf)[i]:=p_tab[pbytearray(buf)[i]];


pbytearray(buf)[i]:=pbytearray(buf)[i] xor cry_t[i];

if dir=1  then pbytearray(buf)[i]:=xsucc(pbytearray(buf)[i],hash_t[i]);


if dir=0 then pbytearray(buf)[i]:=p_dtab[pbytearray(buf)[i]];



end;
end;



function Kolch_Crypt (fi,ft: string;skey: string;dir: byte; process: pprocessproc=nil): boolean;
var Hash: TDCP_SHA512;FileIn, FileOut: TFileStream; Buffer, Dest, IV, XB: array [0..63] of byte; Left, BlockSize: integer;  key: TKey;  i: integer;
begin

FillChar(Cry_t_c[0], 64, 0);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.UpdateStr(skey);
Hash.Final(key);
Hash.Free;

  FileIn := TFileStream.Create(fi,fmOpenRead or fmShareDenyWrite);
  FileOut := TFileStream.Create(ft, fmCreate);
  Left := FileIn.Size;
  FillChar(Buffer,64,0);
  FillChar(Dest,64,0);
  FillChar(XB,64,0);
  InitCipher(key);
  InitPT(key);

move(key, iv, 64);

  repeat
if left<64 then blocksize:=left else blocksize:=64;
  FileIn.Read(Buffer, blocksize);

if dir=1 then
begin

if (key[30] in [125..200]) or (key[15] in [0..125]) or
(key[50] in [200..240]) then
begin
move(p_tab,p_tab_t,256);
move(p_dtab,p_tab,256);
move(p_tab_t,p_dtab,256);
end;


mutatekey(key, key[63]);
mutatetables(key[0]);

XorBuff(@buffer,@iv,blocksize,@dest);

CryptBlock(@Key,64,1);
InitCipher(key);


for i:=0 to NUMROUNDS-1 do CryptBlock(@Dest,blocksize,dir);


Move(dest,iv,blocksize);
end else begin

if (key[30] in [125..200]) or (key[15] in [0..125]) or
(key[50] in [200..240]) then
begin
move(p_tab,p_tab_t,256);
move(p_dtab,p_tab,256);
move(p_tab_t,p_dtab,256);
end;

mutatekey(key, key[63]);
mutatetables(key[0]);


Move(Buffer,XB,blocksize);

CryptBlock(@Key,64,1);
InitCipher(key);


for i:=0 to NUMROUNDS-1 do  CryptBlock(@Buffer,blocksize,dir);




XorBuff(@buffer,@iv,blocksize,@dest);
Move(XB,IV,blocksize);
end;


  FileOut.Write(Dest, blocksize);
if process<>nil then begin
TProcessproc(process)(blocksize);
end;
  dec(left,blocksize);
until left<=0;


FileIn.Destroy;
FileOut.Destroy;
result:=true;
end;




end.
