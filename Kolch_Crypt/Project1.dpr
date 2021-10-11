program Project1;

uses
  Forms,
  Unit1 in 'Unit1.pas' {Form1},
  kolchcrypt in 'KolchCrypt\kolchcrypt.pas',
  crc32 in 'KolchCrypt\crc32.pas',
  DCPbase64 in 'KolchCrypt\DCPbase64.pas',
  DCPconst in 'KolchCrypt\DCPconst.pas',
  DCPcrypt2 in 'KolchCrypt\DCPcrypt2.pas',
  DCPhaval in 'KolchCrypt\DCPhaval.pas',
  DCPsha512 in 'KolchCrypt\DCPsha512.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
