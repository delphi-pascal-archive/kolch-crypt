unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,crc32, kolchcrypt, ComCtrls, StdCtrls;

type
  TForm1 = class(TForm)
    Button1: TButton;
    pg: TProgressBar;
    key: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }

  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function FileSizeByName(const AFilename: string): int64;
begin
  with TFileStream.Create(AFilename, fmOpenRead or fmShareDenyNone) do
    try
      Result := Size;
    finally
      Free;
      end;
end;

procedure pproc(data: integer);
begin
form1.pg.Position:=form1.pg.Position+data
end;


procedure TForm1.Button1Click(Sender: TObject);
var crc1,crc2: cardinal;
begin
crc1:=filecrc32(extractfilepath(application.ExeName)+'test.txt');
pg.Max:=FileSizeByName(extractfilepath(application.ExeName)+'test.txt');
pg.Position:=0;
pg.Min:=0;
kolch_crypt(extractfilepath(application.ExeName)+'test.txt',extractfilepath(application.ExeName)+'test.enc',key.text,1,@pproc);
pg.Max:=FileSizeByName(extractfilepath(application.ExeName)+'test.txt');
pg.Position:=0;
pg.Min:=0;
kolch_crypt(extractfilepath(application.ExeName)+'test.enc',extractfilepath(application.ExeName)+'test.dec',key.text,0,@pproc);
crc2:=filecrc32(extractfilepath(application.ExeName)+'test.dec');
if crc1=crc2 then showmessage('All is fine!') else showmessage('File not decrypted!')
end;

end.
