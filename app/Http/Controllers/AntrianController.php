<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\AntrianBPJSController;
use App\Http\Controllers\API\VclaimBPJSController;
use App\Http\Controllers\API\WhatsappController;
use App\Models\Antrian;
use App\Models\Dokter;
use App\Models\JadwalDokter;
use App\Models\KunjunganDB;
use App\Models\LayananDB;
use App\Models\LayananDetailDB;
use App\Models\ParamedisDB;
use App\Models\PasienDB;
use App\Models\PenjaminDB;
use App\Models\Poliklinik;
use App\Models\Provinsi;
use App\Models\SuratKontrol;
use App\Models\TarifLayananDetailDB;
use App\Models\TracerDB;
use App\Models\TransaksiDB;
use App\Models\UnitDB;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use RealRashid\SweetAlert\Facades\Alert;
use Mike42\Escpos\Printer;
use Mike42\Escpos\PrintConnectors\WindowsPrintConnector;


class AntrianController extends Controller
{
    // console antrian
    public function console()
    {
        $poliklinik = Poliklinik::with(['antrians', 'jadwals'])->where('status', 1)->get();
        $now = Carbon::now();
        $jadwal = JadwalDokter::where('hari',  $now->dayOfWeek)->get();
        return view('simrs.antrian_console', [
            'poliklinik' => $poliklinik,
            'jadwal' => $jadwal,
        ]);
    }
    public function cek_post()
    {
        try {
            $connector = new WindowsPrintConnector(env('PRINTER_CHECKIN'));
            $printer = new Printer($connector);
            $printer->text("Connector Printer :\n");
            $printer->text(env('PRINTER_CHECKIN') . "\n");
            $printer->text("Test Printer Berhasil.\n");
            $printer->cut();
            $printer->close();
            Alert::success('Success', 'Mesin menyala dan siap digunakan.');
            return redirect()->route('antrian.console');
        } catch (\Throwable $th) {
            //throw $th;
            Alert::error('Error', 'Mesin antrian tidak menyala. Silahkan hubungi admin.');
            return redirect()->route('antrian.console');
        }
    }
    function print_karcis(Request $request,  $kunjungan)
    {
        Carbon::setLocale('id');
        date_default_timezone_set('Asia/Jakarta');
        $now = Carbon::now();
        $connector = new WindowsPrintConnector(env('PRINTER_CHECKIN'));
        $printer = new Printer($connector);
        $printer->setEmphasis(true);
        $printer->text("ANTRIAN RAWAT JALAN\n");
        $printer->text("RSUD WALED KAB. CIREBON\n");
        $printer->setEmphasis(false);
        $printer->text("================================================\n");
        $printer->text("No. RM : " . $request->norm . "\n");
        $printer->text("Nama : " . $request->nama . "\n");
        $printer->text("NIK : " . $request->nik . "\n");
        $printer->text("No. Kartu JKN : " . $request->nomorkartu . "\n");
        $printer->text("No. Telp. : " . $request->nohp . "\n");
        $printer->text("No. Rujukan : " . $request->nomorrujukan . "\n");
        $printer->text("No. Surat Kontrol : " . $request->nomorsuratkontrol . "\n");
        $printer->text("No. SEP : " . $request->nomorsep . "\n");
        $printer->text("================================================\n");
        $printer->text("Jenis Kunj. : " . $request->jeniskunjungan_print . "\n");
        $printer->text("Poliklinik : " . $request->namapoli . "\n");
        $printer->text("Dokter : " . $request->namadokter . "\n");
        $printer->text("Jam Praktek : " . $request->jampraktek . "\n");
        $printer->text("Tanggal : " . Carbon::parse($request->tanggalperiksa)->format('d M Y') . "\n");
        $printer->text("================================================\n");
        $printer->text("Keterangan : \n" . $request->keterangan . "\n");
        if (empty($request->nomorreferensi)) {
            $printer->text("================================================\n");
            $printer->setJustification(Printer::JUSTIFY_RIGHT);
            $printer->text("Biaya Karcis Poli : " . money($request->tarifkarcis, 'IDR') . "\n");
            $printer->text("Biaya Administrasi : " . money($request->tarifadm, 'IDR') . "\n");
        }
        $printer->text("================================================\n");
        $printer->setJustification(Printer::JUSTIFY_CENTER);
        $printer->text("Jenis Pasien :\n");
        $printer->setTextSize(2, 2);
        $printer->text($request->jenispasien . " " . $request->pasienbaru_print . "\n");
        $printer->setTextSize(1, 1);
        $printer->text("Kode Booking : " . $request->kodebooking . "\n");
        $printer->text("Kode Kunjungan : " . $kunjungan->kode_kunjungan . "\n");
        $printer->qrCode($request->kodebooking, Printer::QR_ECLEVEL_L, 10, Printer::QR_MODEL_2);
        $printer->text("================================================\n");
        $printer->text("Nomor Antrian Poliklinik :\n");
        $printer->setTextSize(2, 2);
        $printer->text($request->nomorantrean . "\n");
        $printer->setTextSize(1, 1);
        $printer->text("Lokasi Poliklinik Lantai " . $request->lokasi . " \n");
        $printer->text("================================================\n");
        $printer->text("Angka Antrian :\n");
        $printer->setTextSize(2, 2);
        $printer->text($request->angkaantrean . "\n");
        $printer->setTextSize(1, 1);
        $printer->text("Lokasi Pendaftaran Lantai " . $request->lantaipendaftaran . " \n");
        $printer->text("================================================\n");
        $printer->setJustification(Printer::JUSTIFY_LEFT);
        $printer->text("Cetakan 1 : " . $now . "\n");
        $printer->cut();
        $printer->close();
    }
    function print_sep(Request $request, $sep)
    {
        Carbon::setLocale('id');
        date_default_timezone_set('Asia/Jakarta');
        $now = Carbon::now();
        $for_sep = ['POLIKLINIK', 'FARMASI', 'ARSIP'];
        // $for_sep = ['PERCOBAAN'];
        $sep = $sep->response;
        foreach ($for_sep as  $value) {
            $connector = new WindowsPrintConnector(env('PRINTER_CHECKIN'));
            $printer = new Printer($connector);
            $printer->setEmphasis(true);
            $printer->text("SURAT ELEGTABILITAS PASIEN (SEP)\n");
            $printer->text("RSUD WALED KAB. CIREBON\n");
            $printer->setEmphasis(false);
            $printer->text("================================================\n");
            $printer->setJustification(Printer::JUSTIFY_CENTER);
            $printer->text("Nomor SEP :\n");
            $printer->setTextSize(2, 2);
            $printer->text($sep->sep->noSep . "\n");
            $printer->setTextSize(1, 1);
            $printer->qrCode($sep->sep->noSep, Printer::QR_ECLEVEL_L, 10, Printer::QR_MODEL_2);
            $printer->text("Tgl SEP : " . $sep->sep->tglSep . " \n");
            $printer->text("SEP untuk " . $value . "\n");
            $printer->setJustification(Printer::JUSTIFY_LEFT);
            $printer->text("================================================\n");
            $printer->text("Nama Pasien : " . $sep->sep->peserta->nama . " \n");
            $printer->text("Nomor Kartu : " . $sep->sep->peserta->noKartu . " \n");
            $printer->text("No. RM : " . $request->norm . "\n");
            $printer->text("No. Telepon : " . $request->nohp . "\n");
            $printer->text("Jenis Peserta : " . $sep->sep->peserta->jnsPeserta . " \n\n");

            $printer->text("Jenis Pelayanan : " . $sep->sep->jnsPelayanan . " \n");
            $printer->text("Poli / Spesialis : " . $sep->sep->poli . "\n");
            $printer->text("Hak Kelas : " . $sep->sep->kelasRawat . " \n");
            $printer->text("COB : -\n");
            $printer->text("Diagnosa Awal : " . $sep->sep->diagnosa . "\n");
            $printer->text("Faskes Perujuk : -\n");
            $printer->text("Catatan : " . $sep->sep->catatan . "\n\n");
            $printer->setJustification(Printer::JUSTIFY_RIGHT);
            $printer->text("Cirebon, " . $now->format('d-m-Y') . " \n\n\n\n");
            $printer->text("RSUD Waled \n\n");
            $printer->setJustification(Printer::JUSTIFY_LEFT);
            $printer->text("Cetakan : " . $now . "\n");
            $printer->cut();
            $printer->close();
        }
    }
    public function console_jadwaldokter($poli, $tanggal)
    {
        $poli = Poliklinik::with(['jadwals'])->firstWhere('kodesubspesialis', $poli);
        $jadwals = $poli->jadwals->where('hari', Carbon::parse($tanggal)->dayOfWeek)
            ->where('kodesubspesialis', $poli->kodesubspesialis);
        return response()->json($jadwals);
    }
    public function tambah_offline($poli, $dokter, $jadwal)
    {
        $tanggal = Carbon::now()->format('Y-m-d');
        $antrian_dokter = Antrian::where('tanggalperiksa', $tanggal)
            ->where('kodepoli', $poli)
            ->where('kodedokter', $dokter)
            ->count();
        $poli = Poliklinik::where('kodesubspesialis', $poli)->first();
        $jadwal = $poli->jadwals->where('hari', Carbon::parse($tanggal)->dayOfWeek)->where('kodedokter', $dokter)->first();
        if ($jadwal->libur) {
            Alert::error('Error', 'Jadwal Dokter sedang Libur / Ditutup');
            return redirect()->route('antrian.console');
        }
        $dokter = Dokter::where('kodedokter', $dokter)->first();
        if ($antrian_dokter >= $jadwal->kapasitaspasien) {
            Alert::error('Error', 'Antrian poliklinik jadwal dokter tersebut telah penuh');
            return redirect()->route('antrian.console');
        }
        return view('simrs.antrian_tambah_offline', [
            'jadwal' => $jadwal,
            'tanggal' => $tanggal,
        ]);
    }
    public function store_offline(Request $request)
    {
        // cek printer dulu
        try {
            $connector = new WindowsPrintConnector(env('PRINTER_CHECKIN'));
            $printer = new Printer($connector);
            $printer->close();
        } catch (\Throwable $th) {
            //throw $th;
            Alert::error('Error', 'Mesin antrian tidak menyala. Silahkan hubungi admin.');
            return redirect()->route('antrian.console');
        }
        // get pasien
        $pasien = PasienDB::where('no_rm', 'like', '%' . $request->norm)->first();
        $unit = UnitDB::firstWhere('KDPOLI', $request->kodepoli);
        $now = Carbon::now();
        // get kode tarif layanan detail
        $tarifkarcis = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_karcis);
        $tarifadm = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_adm);
        $pasien->update([
            'no_tlp' => $request->nohp,
            'no_hp' => $request->nohp,
        ]);
        $request['norm'] = $pasien->no_rm;
        $request['noKartu'] = $request->nomorkartu;
        $request['tglSep'] = $request->tanggalperiksa;
        $request['noMR'] = $request->norm;
        $request['nik'] = $request->nik;
        $request['nohp'] = $request->nohp;
        $request['kodedokter'] = $request->kodedokter;
        // cek duplikasi nik antrian
        // $antrian_nik = Antrian::where('tanggalperiksa', $request->tanggalperiksa)
        //     ->where('nik', $request->nik)
        //     ->where('taskid', '<=', 4)
        //     ->count();
        // if ($antrian_nik) {
        //     Alert::error('Error',  'Terdapat antrian dengan nomor NIK yang sama pada tanggal tersebut yang belum selesai. ' . $request->nik);
        //     return redirect()->route('antrian.console');
        // }
        // pasien jkn
        if (isset($request->nomorreferensi)) {
            $request['jenispasien'] = "JKN";
            $request['taskid'] = "3";
            $request['status_api'] = "1";
            $penjamin = PenjaminDB::where('nama_penjamin_bpjs', $request->jenispenjamin)->first();
            $request['kodepenjamin'] = $penjamin->kode_penjamin_simrs;
            $request['keterangan'] = "Silahkan menunggu panggilan dipoliklinik.";
            // rj jkn tipe transaki 2 status layanan 2 status layanan detail opn
            $tipetransaksi = 2;
            $statuslayanan = 2;
            // rj jkn masuk ke tagihan penjamin
            $tagihanpenjamin = $tarifkarcis->TOTAL_TARIF_NEW;
            $totalpenjamin =  $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW;
            $tagihanpribadi = 0;
            $totalpribadi =  0;
            // insert sep
            $vclaim = new VclaimBPJSController();
            // daftar pake surat kontrol
            if ($request->jeniskunjungan == 3) {
                $suratkontrol = $vclaim->surat_kontrol_nomor($request);
                $request['nomorsuratkontrol'] = $request->nomorreferensi;
                $request['nomorrujukan'] = $suratkontrol->response->sep->provPerujuk->noRujukan;
                $request['nomorreferensi'] = $request->nomorrujukan;
                $data = $vclaim->rujukan_nomor($request);
                if ($data->metaData->code == 200) {
                    $rujukan = $data->response->rujukan;
                    $peserta = $rujukan->peserta;
                    $diganosa = $rujukan->diagnosa;
                    $tujuan = $rujukan->poliRujukan;
                    // tujuan rujukan
                    $request['ppkPelayanan'] = "1018R001";
                    $request['jnsPelayanan'] = "2";
                    // peserta
                    $request['klsRawatHak'] = $peserta->hakKelas->kode;
                    $request['klsRawatNaik'] = "";
                    // $request['pembiayaan'] = $peserta->jenisPeserta->kode;
                    // $request['penanggungJawab'] =  $peserta->jenisPeserta->keterangan;
                    // asal rujukan
                    $request['asalRujukan'] = $data->response->asalFaskes;
                    $request['tglRujukan'] = $rujukan->tglKunjungan;
                    $request['noRujukan'] =   $rujukan->noKunjungan;
                    $request['ppkRujukan'] = $rujukan->provPerujuk->kode;
                    // diagnosa
                    $request['catatan'] =  $diganosa->nama;
                    $request['diagAwal'] =  $diganosa->kode;
                    // poli tujuan
                    $request['tujuan'] =  $tujuan->kode;
                    $request['eksekutif'] =  0;
                    // dpjp
                    // dd($suratkontrol->response->kodeDokter);
                    $request['tujuanKunj'] = "2";
                    $request['flagProcedure'] = "";
                    $request['kdPenunjang'] = "";
                    $request['assesmentPel'] = "5";
                    $request['noSurat'] = $request->nomorsuratkontrol;
                    $request['kodeDPJP'] = $suratkontrol->response->kodeDokter;
                    $request['dpjpLayan'] =  $suratkontrol->response->kodeDokter;
                } else {
                    return [
                        "metadata" => [
                            "message" => $data->metaData->message,
                            "code" => 201,
                        ],
                    ];
                }
                $sep = $vclaim->insert_sep($request);
            }
            // daftar pake rujukan
            else {
                $request['nomorrujukan'] = $request->nomorreferensi;
                // cek rujukan
                $data = $vclaim->rujukan_nomor($request);
                if ($data->metaData->code == 200) {
                    $rujukan = $data->response->rujukan;
                    $peserta = $rujukan->peserta;
                    $diganosa = $rujukan->diagnosa;
                    $tujuan = $rujukan->poliRujukan;
                    // tujuan rujukan
                    $request['ppkPelayanan'] = "1018R001";
                    $request['jnsPelayanan'] = "2";
                    // peserta
                    $request['klsRawatHak'] = $peserta->hakKelas->kode;
                    $request['klsRawatNaik'] = "";
                    // $request['pembiayaan'] = $peserta->jenisPeserta->kode;
                    // $request['penanggungJawab'] =  $peserta->jenisPeserta->keterangan;
                    // asal rujukan
                    $request['asalRujukan'] = $data->response->asalFaskes;
                    $request['tglRujukan'] = $rujukan->tglKunjungan;
                    $request['noRujukan'] =   $request->nomorreferensi;
                    $request['ppkRujukan'] = $rujukan->provPerujuk->kode;
                    // diagnosa
                    $request['catatan'] =  $diganosa->nama;
                    $request['diagAwal'] =  $diganosa->kode;
                    // poli tujuan
                    $request['tujuan'] =  $tujuan->kode;
                    $request['eksekutif'] =  0;
                    // dpjp
                    $request['tujuanKunj'] = "0";
                    $request['flagProcedure'] = "";
                    $request['kdPenunjang'] = "";
                    $request['assesmentPel'] = "";
                    $request['noSurat'] = "";
                    $request['kodeDPJP'] = "";
                    $request['dpjpLayan'] = $request->kodedokter;
                } else {
                    return [
                        "metadata" => [
                            "message" => $data->metaData->message,
                            "code" => 201,
                        ],
                    ];
                }
                // create sep
                $sep = $vclaim->insert_sep($request);
            }
            // print sep
            if ($sep->metaData->code == 200) {
                $request["nomorsep"] = $sep->response->sep->noSep;
                $this->print_sep($request, $sep);
            } else {
                Alert::error('Error',  'Tidak bisa membuat SEP karena ' . $sep->metaData->message);
                return redirect()->route('antrian.console');
            }
            if ($request->jeniskunjungan == 3) {
                $request['jeniskunjungan_print'] = "KONTROL";
            } else {
                $request['jeniskunjungan_print'] = "RUJUKAN";
            }
        }
        // pasien non-jkn
        else {
            $request['jenispasien'] = "NON-JKN";
            $request['taskid'] = "3";
            $request['kodepenjamin'] = "P01";
            $request['status_api'] = "0";
            $request['keterangan'] = "Silahkan lakukan pembayaran terlebih dahulu diloket pembayaran rawat jalan lantai 1.";
            $request['jeniskunjungan_print'] = "KUNJUNGAN UMUM";
            // rj umum tipe transaki 1 status layanan 1 status layanan detail opn
            $tipetransaksi = 1;
            $statuslayanan = 1;
            // rj umum masuk ke tagihan pribadi
            $tagihanpenjamin = 0;
            $totalpenjamin =  0;
            $tagihanpribadi = $tarifkarcis->TOTAL_TARIF_NEW;
            $totalpribadi = $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW;
        }
        if ($request->pasienbaru == 1) {
            $request['pasienbaru_print'] = "BARU";
        } else {
            $request['pasienbaru_print'] = "LAMA";
        }
        // get jadwal
        $poli = Poliklinik::where('kodepoli', $request->kodepoli)->first();
        $request['lokasi'] =  $poli->lokasi;
        $request['lantaipendaftaran'] =  $poli->lantaipendaftaran;
        $jadwals = JadwalDokter::where("kodepoli", $request->kodepoli)->where("hari",  Carbon::parse($request->tanggalperiksa)->dayOfWeek)->get();
        $jadwal = $jadwals->where('kodedokter', $request->kodedokter)->first();
        $request['namapoli'] = $jadwal->namapoli;
        $request['namadokter'] = $jadwal->namadokter;
        // get antrian
        $antrians = Antrian::where('tanggalperiksa', $request->tanggalperiksa)
            ->count();
        $antrian_poli = Antrian::where('tanggalperiksa', $request->tanggalperiksa)
            ->where('kodepoli', $request->kodepoli)
            ->count();
        $antrianjkn = Antrian::where('kodepoli', $request->kodepoli)
            ->where('tanggalperiksa', $request->tanggalperiksa)
            ->where('jenispasien', "JKN")->count();
        $antriannonjkn = Antrian::where('kodepoli', $request->kodepoli)
            ->where('tanggalperiksa', $request->tanggalperiksa)
            ->where('jenispasien', "NON-JKN")->count();
        $request['kodebooking'] = strtoupper(uniqid());
        $request['pasienbaru'] = 0;
        $request['nomorantrean'] = $request->kodepoli . "-" .  str_pad($antrian_poli + 1, 3, '0', STR_PAD_LEFT);
        $request['angkaantrean'] = $antrians + 1;
        $request['kodebooking'] = strtoupper(uniqid());
        // estimasi
        $jadwalbuka = Carbon::parse($request->tanggalperiksa . ' ' . explode('-', $request->jampraktek)[0])->addMinutes(5 * ($antrian_poli + 1));
        $request['estimasidilayani'] = $jadwalbuka->timestamp * 1000;
        $request['sisakuotajkn'] = round($jadwal->kapasitaspasien * 80 / 100) -  $antrianjkn - 1;
        $request['kuotajkn'] = round($jadwal->kapasitaspasien * 80 / 100);
        $request['sisakuotanonjkn'] = round($jadwal->kapasitaspasien * 20 / 100) - $antriannonjkn - 1;
        $request['kuotanonjkn'] = round($jadwal->kapasitaspasien * 20 / 100);
        $antrian = new AntrianBPJSController();
        $tambah_antrian = $antrian->tambah_antrian($request);
        if ($tambah_antrian->metadata->code == 200) {
            $request['waktu'] = $now->timestamp * 1000;
            $update_antrian = $antrian->update_antrian($request);
            if ($update_antrian->metadata->code == 200) {
                // insert simrs
                try {
                    $paramedis = ParamedisDB::firstWhere('kode_dokter_jkn', $request->kodedokter);
                    // hitung counter kunjungan
                    $kunjungan = KunjunganDB::where('no_rm', $request->norm)->orderBy('counter', 'DESC')->first();
                    if (empty($kunjungan)) {
                        $counter = 1;
                    } else {
                        $counter = $kunjungan->counter + 1;
                    }
                    // insert ts kunjungan
                    KunjunganDB::create(
                        [
                            'counter' => $counter,
                            'no_rm' => $request->norm,
                            'kode_unit' => $unit->kode_unit,
                            'tgl_masuk' => $now,
                            'kode_paramedis' => $paramedis->kode_paramedis,
                            'status_kunjungan' => 1,
                            'prefix_kunjungan' => $unit->prefix_unit,
                            'kode_penjamin' => $request->kodepenjamin,
                            'pic' => 1319,
                            'id_alasan_masuk' => 1,
                            'kelas' => 3,
                            'hak_kelas' => $request->hakkelas,
                            'no_sep' =>  $request->nomorsep,
                            'no_rujukan' => $request->nomorrujukan,
                            'diagx' =>  $request->diagnosa,
                            'created_at' => $now,
                            'keterangan2' => 'MESIN_2',
                        ]
                    );
                    $kunjungan = KunjunganDB::where('no_rm', $request->norm)->where('counter', $counter)->first();
                    // get transaksi sebelumnya
                    $trx_lama = TransaksiDB::where('unit', $unit->kode_unit)
                        ->whereBetween('tgl', [Carbon::now()->startOfDay(), [Carbon::now()->endOfDay()]])
                        ->count();
                    // get kode layanan
                    $kodelayanan = $unit->prefix_unit . $now->format('y') . $now->format('m') . $now->format('d')  . str_pad($trx_lama + 1, 6, '0', STR_PAD_LEFT);
                    //  insert transaksi
                    $trx_baru = TransaksiDB::create([
                        'tgl' => $now->format('Y-m-d'),
                        'no_trx_layanan' => $kodelayanan,
                        'unit' => $unit->kode_unit,
                    ]);
                    //  insert layanan header
                    $layananbaru = LayananDB::create(
                        [
                            'kode_layanan_header' => $kodelayanan,
                            'tgl_entry' => $now,
                            'kode_kunjungan' => $kunjungan->kode_kunjungan,
                            'kode_unit' => $unit->kode_unit,
                            'kode_tipe_transaksi' => $tipetransaksi,
                            'status_layanan' => $statuslayanan,
                            'status_pembayaran' => 'OPN',
                            'status_retur' => 'OPN',
                            'pic' => '1319',
                            'keterangan' => 'Layanan header melalui antrian sistem untuk pasien ' . $request->jenispasien,
                        ]
                    );
                    //  insert layanan header dan detail karcis admin konsul 25 + 5 = 30
                    //  insert layanan detail karcis
                    $karcis = LayananDetailDB::create(
                        [
                            'id_layanan_detail' => "DET" . $now->yearIso . $now->month . $now->day .  "001",
                            'row_id_header' => $layananbaru->id,
                            'kode_layanan_header' => $layananbaru->kode_layanan_header,
                            'kode_tarif_detail' => $tarifkarcis->KODE_TARIF_DETAIL,
                            'total_tarif' => $tarifkarcis->TOTAL_TARIF_NEW,
                            'jumlah_layanan' => 1,
                            'tagihan_pribadi' => $tagihanpribadi,
                            'tagihan_penjamin' => $tagihanpenjamin,
                            'total_layanan' => $tarifkarcis->TOTAL_TARIF_NEW,
                            'grantotal_layanan' => $tarifkarcis->TOTAL_TARIF_NEW,
                            'kode_dokter1' => $paramedis->kode_paramedis, // ambil dari mt paramdeis
                            'tgl_layanan_detail' =>  $now,
                        ]
                    );
                    //  insert layanan detail admin
                    $adm = LayananDetailDB::create(
                        [
                            'id_layanan_detail' => "DET" . $now->yearIso . $now->month . $now->day .  "01",
                            'row_id_header' => $layananbaru->id,
                            'kode_layanan_header' => $layananbaru->kode_layanan_header,
                            'kode_tarif_detail' => $tarifadm->KODE_TARIF_DETAIL,
                            'total_tarif' => $tarifadm->TOTAL_TARIF_NEW,
                            'jumlah_layanan' => 1,
                            'tagihan_pribadi' => $tagihanpribadi,
                            'tagihan_penjamin' => $tagihanpenjamin,
                            'total_layanan' => $tarifadm->TOTAL_TARIF_NEW,
                            'grantotal_layanan' => $tarifadm->TOTAL_TARIF_NEW,
                            'kode_dokter1' => 0,
                            'tgl_layanan_detail' =>  $now,
                        ]
                    );
                    //  update layanan header total tagihan
                    $layananbaru->update([
                        'total_layanan' => $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW,
                        'tagihan_pribadi' => $totalpribadi,
                        'tagihan_penjamin' => $totalpenjamin,
                    ]);
                    $request['tarifkarcis'] = $tarifkarcis->TOTAL_TARIF_NEW;
                    $request['tarifadm'] = $tarifadm->TOTAL_TARIF_NEW;
                    // insert tracer tc_tracer_header
                    $tracerbaru = TracerDB::create([
                        'kode_kunjungan' => $kunjungan->kode_kunjungan,
                        'tgl_tracer' => $now->format('Y-m-d'),
                        'id_status_tracer' => 1,
                        'cek_tracer' => "N",
                    ]);
                    // print karcis
                    $this->print_karcis($request, $kunjungan);
                    // kirim notif wa
                    $wa = new WhatsappController();
                    $request['message'] = "Antrian berhasil didaftarkan melalui Mesin Self-Ticketing dengan data sebagai berikut : \n\n*Kode Antrian :* " . $request->kodebooking .  "\n*Angka Antrian :* " . $request->angkaantrean .  "\n*Nomor Antrian :* " . $request->nomorantrean .  "\n\n*Nama :* " . $request->nama . "\n*Jenis Pasien :* " . $request->jenispasien . " " . $request->pasienbaru_print  . "\n*Poliklinik :* " . $request->namapoli  . "\n*Dokter :* " . $request->namadokter  .  "\n*Tanggal Berobat :* " . $request->tanggalperiksa .  "\n*Jam Praktek :* " . $request->jampraktek  . "\n\n*Keterangan :* " . $request->keterangan  .  "\nTerima kasih. Semoga sehat selalu.\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
                    $request['number'] = $request->nohp;
                    $wa->send_message($request);
                } catch (\Throwable $th) {
                    //throw $th;
                    return [
                        "metadata" => [
                            "message" => $th->getMessage(),
                            "code" => 201,
                        ],
                    ];
                }
                // masuk database
                Antrian::create([
                    "kodebooking" => $request->kodebooking,
                    "nomorkartu" => $request->nomorkartu,
                    "nama" => $request->nama,
                    "nik" => $request->nik,
                    "nohp" => $request->nohp,
                    "kodepoli" => $request->kodepoli,
                    "norm" => $request->norm,
                    "pasienbaru" => $request->pasienbaru,
                    "tanggalperiksa" => $request->tanggalperiksa,
                    "kodedokter" => $request->kodedokter,
                    "jampraktek" => $request->jampraktek,
                    "jeniskunjungan" => $request->jeniskunjungan,
                    "nomorreferensi" => $request->nomorreferensi,
                    // surat kontrol
                    "nomorrujukan" => $request->nomorrujukan,
                    "nomorsuratkontrol" => $request->nomorsuratkontrol,
                    "nomorsep" => $request->nomorsep,
                    "jenispasien" => $request->jenispasien,
                    "namapoli" => $request->namapoli,
                    "namadokter" => $request->namadokter,
                    "nomorantrean" => $request->nomorantrean,
                    "angkaantrean" => $request->angkaantrean,
                    "estimasidilayani" => $request->estimasidilayani,
                    "lokasi" => $poli->lokasi,
                    "lantaipendaftaran" => $poli->lantaipendaftaran,
                    "sisakuotajkn" => $request->sisakuotajkn,
                    "kuotajkn" => $request->kuotajkn,
                    "sisakuotanonjkn" => $request->sisakuotanonjkn,
                    "kuotanonjkn" => $request->kuotanonjkn,
                    "keterangan" => $request->keterangan,
                    "status_api" => $request->status_api,
                    "taskid" =>  $request->taskid,
                    "taskid3" =>  $now,
                    "user" => "System Antrian",
                ]);
                Alert::success('Success',  'Antrian berhasil didaftarkan.');
                return redirect()->route('antrian.console');
            } else {
                Alert::error('Error',  'Update Antrian Gagal.');
                return redirect()->route('antrian.console');
            }
        } else {
            Alert::error('Error',  'Tidak bisa mendaftarkan antrian ' . $tambah_antrian->metadata->message);
            return redirect()->route('antrian.console');
        }
    }
    public function taskid(Request $request)
    {
        $response = null;
        $api = new AntrianBPJSController();
        if ($request->kodebooking) {
            $response = $api->list_waktu_task($request);
        }
        return view('simrs.antrian_task_id', [
            'request' => $request,
            'response' => $response,
        ]);
    }
    public function checkin_update(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "waktu" => "required|numeric",
        ]);
        if ($validator->fails()) {
            $response = [
                'metadata' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return $response;
        }
        // cari antrian
        $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
        if (isset($antrian)) {
            $api = new AntrianBPJSController();
            $response = json_decode(json_encode($api->checkin_antrian($request)));
            return $response;
        }
        // jika antrian tidak ditemukan
        else {
            return $response = [
                'metadata' => [
                    'code' => 400,
                    'message' => "Antrian tidak ditemukan",
                ],
            ];
        }
    }
    // pendaftaran
    public function pendaftaran(Request $request)
    {
        $antrians = [];
        if ($request->tanggal) {
            $antrians = Antrian::where('tanggalperiksa', $request->tanggal)
                ->where('lantaipendaftaran',  $request->lantai)
                ->get();
        }
        $provinsis = Provinsi::get();
        return view('simrs.antrian_pendaftaran', [
            'antrians' => $antrians,
            'request' => $request,
            'provinsis' => $provinsis,
        ]);
    }
    public function panggil_pendaftaran($kodebooking, $loket, $lantai, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        if ($antrian) {
            $request['kodebooking'] = $antrian->kodebooking;
            $request['taskid'] = 2;
            $now = Carbon::now();
            $request['waktu'] = Carbon::now()->timestamp * 1000;
            $vclaim = new AntrianBPJSController();
            $response = $vclaim->update_antrian($request);
            $antrian->update([
                'taskid' => 2,
                'status_api' => 1,
                'keterangan' => "Panggilan ke loket pendaftaran",
                'taskid2' => $now,
                // 'user' => Auth::user()->name,
            ]);

            //panggil urusan mesin antrian
            try {
                // notif wa
                $wa = new WhatsappController();
                $request['message'] = "Panggilan kepada Antrian dengan kode booking " . $antrian->kodebooking . " untuk melakukan pendaftaran di Loket pendaftaran.";
                $request['number'] = $antrian->nohp;
                $wa->send_message($request);

                $tanggal = Carbon::now()->format('Y-m-d');
                $urutan = $antrian->angkaantrean;
                $mesin_antrian = DB::connection('mysql3')->table('tb_counter')
                    ->where('tgl', $tanggal)
                    ->where('kategori', 'JKN')
                    ->where('loket', $loket)
                    ->where('lantai', $lantai)
                    ->get();
                if ($mesin_antrian->count() < 1) {
                    $mesin_antrian = DB::connection('mysql3')->table('tb_counter')->insert([
                        'tgl' => $tanggal,
                        'kategori' => 'JKN',
                        'loket' => $loket,
                        'counterloket' => $urutan,
                        'lantai' => $lantai,
                        'mastercount' => $urutan,
                        'sound' => 'PLAY',
                    ]);
                } else {
                    DB::connection('mysql3')->table('tb_counter')
                        ->where('tgl', $tanggal)
                        ->where('kategori', 'JKN')
                        ->where('loket', $loket)
                        ->where('lantai', $lantai)
                        ->limit(1)
                        ->update([
                            // 'counterloket' => $antrian->first()->mastercount + 1,
                            'counterloket' => $urutan,
                            // 'mastercount' => $antrian->first()->mastercount + 1,
                            'mastercount' => $urutan,
                            'sound' => 'PLAY',
                        ]);
                }
            } catch (\Throwable $th) {
                Alert::error('Error', $th->getMessage());
                return redirect()->back();
            }
            Alert::success('Success', 'Panggilan Berhasil ' . $response->metadata->message);
            return redirect()->back();
        } else {
            Alert::error('Error', 'Kode Booking tidak ditemukan');
            return redirect()->back();
        }
    }
    public function cari_pasien($nik)
    {
        $pasien = PasienDB::where('nik_bpjs', $nik)->first();
        if ($pasien == null) {
            $code = 201;
            $message = "Pasien Tidak Ditemukan. Silahkan daftarkan pasien.";
        } else {
            $message = "Pasien Ditemukan";
            $code = 200;
        }
        $response = [
            "response" => $pasien,
            "metadata" => [
                "message" => $message,
                "code" => $code,
            ]
        ];
        return $response;
    }
    public function update_pendaftaran_offline(Request $request)
    {
        // validation
        $request->validate([
            'antrianid' => 'required',
            'statuspasien' => 'required',
            'nik' => 'required|digits:16',
            'nama' => 'required',
            'nohp' => 'required',
            'jeniskunjungan' => 'required',
            'tanggalperiksa' => 'required',
            'kodepoli' => 'required',
            'kodedokter' => 'required',
        ]);
        if ($request->statuspasien == "BARU") {
            $request->validate([
                'jeniskelamin' => 'required',
                'tanggallahir' => 'required',
                'alamat' => 'required',
                'kodeprop' => 'required',
            ]);
        }
        // init
        $poli = Poliklinik::where('kodesubspesialis', $request->kodepoli)->first();
        $api = new AntrianBPJSController();
        // jika pasien jkn
        if (isset($request->nomorreferensi)) {
            $jenispasien = 'JKN';
            $request['keterangan'] = "Untuk pasien JKN silahkan menunggu diruang tunggu poliklinik";
            $request['status_api'] = 1;
            // insert sep
            // $vclaim = new VclaimBPJSController();
            // $request['noKartu'] = $request->nomorkartu;
            // $request['tglSep'] = Carbon::now()->format('Y-m-d');
            // $request['noMR'] = $request->norm;
            // $request['nik'] = $request->nik;
            // $request['nohp'] = $request->nohp;
            // $request['kodedokter'] = $request->kodedokter;
            // $request['nomorreferensi'] = $request->nomorreferensi;
            // $request['ppkPelayanan'] = "1018R001";
            // $request['jnsPelayanan'] = "2";
            // $data = $vclaim->rujukan_nomor($request);
            // if ($data->metaData->code == 200) {
            //     $rujukan = $data->response->rujukan;
            //     $peserta = $rujukan->peserta;
            //     $diganosa = $rujukan->diagnosa;
            //     $tujuan = $rujukan->poliRujukan;
            //     // tujuan rujukan
            //     $request['ppkPelayanan'] = "1018R001";
            //     $request['jnsPelayanan'] = "2";
            //     // peserta
            //     // $request['klsRawatHak'] = $peserta->hakKelas->kode;
            //     // $request['klsRawatNaik'] = "";
            //     // $request['pembiayaan'] = $peserta->jenisPeserta->kode;
            //     // $request['penanggungJawab'] =  $peserta->jenisPeserta->keterangan;
            //     // asal rujukan
            //     $request['asalRujukan'] = $data->response->asalFaskes;
            //     $request['tglRujukan'] = $rujukan->tglKunjungan;
            //     $request['noRujukan'] =   $request->nomorreferensi;
            //     $request['ppkRujukan'] = $rujukan->provPerujuk->kode;
            //     // diagnosa
            //     $request['catatan'] =  $diganosa->nama;
            //     $request['diagAwal'] =  $diganosa->kode;
            //     // poli tujuan
            //     $request['tujuan'] =  "INT";
            //     $request['eksekutif'] =  0;
            //     // dpjp
            //     // $request['dpjpLayan'] =  $request->kodedokter;
            // }
            // if ($request->nomorsuratkontrol) {
            //     $request['tujuanKunj'] = "1";
            //     $request['flagProcedure'] = "";
            //     $request['kdPenunjang'] = "";
            //     $request['assesmentPel'] = "5";
            //     $request['noSurat'] = $request->nomorsuratkontrol;
            //     $request['kodeDPJP'] = $request->kodedokter;
            //     $request['dpjpLayan'] = $request->kodedokter;
            // } else {
            //     $request['tujuanKunj'] = "2";
            //     $request['flagProcedure'] = "";
            //     $request['kdPenunjang'] = "";
            //     $request['assesmentPel'] = "";
            //     $request['noSurat'] = $request->nomorsuratkontrol;
            //     $request['kodeDPJP'] = $request->kodedokter;
            //     $request['dpjpLayan'] = $request->kodedokter;
            // }
            // $sep = $vclaim->insert_sep($request);
            // dd($sep);
        }
        // jika pasien non-jkn
        else {
            $jenispasien = 'NON-JKN';
            $request['keterangan'] = "Untuk pasien NON-JKN silahkan untuk membayar biaya pendaftaran diloket pembayaran";
            $request['status_api'] = 0;
        }
        $antrian = Antrian::find($request->antrianid);
        $waktu1 = Carbon::parse($antrian->taskid1)->timestamp * 1000;
        $waktu2 = Carbon::parse($antrian->taskid2)->timestamp * 1000;
        $waktu3 =  Carbon::now()->timestamp * 1000;
        $request['kodebooking'] = $antrian->kodebooking;
        $request['nomorantrean'] = $antrian->nomorantrean;
        $request['angkaantrean'] = $antrian->angkaantrean;
        $request['jenispasien'] = $jenispasien;
        $request['estimasidilayani'] = 0;
        $request['sisakuotajkn'] = 5;
        $request['sisakuotanonjkn'] = 5;
        $request['kuotajkn'] = 20;
        $request['kuotanonjkn'] = 20;
        $request['namapoli'] = $poli->namapoli;
        $request['kodepoli'] = $poli->kodepoli;
        // update pasien baru
        if ($request->statuspasien == "BARU") {
            $request['pasienbaru'] = 1;
            $pasien_terakhir = PasienDB::latest()->first()->no_rm;
            $request['status'] = 1;
            $request['norm'] = $pasien_terakhir + 1;
            $pasien = PasienDB::updateOrCreate(
                [
                    "no_Bpjs" => $request->nomorkartu,
                    "nik_bpjs" => $request->nik,
                    "no_rm" => $request->norm,
                ],
                [
                    // "nomorkk" => $request->nomorkk,
                    "nama_px" => $request->nama,
                    "jenis_kelamin" => $request->jeniskelamin,
                    "tgl_lahir" => $request->tanggallahir,
                    "no_tlp" => $request->nohp,
                    "alamat" => $request->alamat,
                    "kode_propinsi" => $request->kodeprop,
                    // "namaprop" => $request->namaprop,
                    "kode_kabupaten" => $request->kodedati2,
                    // "namadati2" => $request->namadati2,
                    "kode_kecamatan" => $request->kodekec,
                    // "namakec" => $request->namakec,
                    "kode_desa" => $request->kodekel,
                    // "namakel" => $request->namakel,
                    // "rw" => $request->rw,
                    // "rt" => $request->rt,
                    // "status" => $request->status,
                ]
            );
        }
        // update pasien lama
        else {
            $pasien = PasienDB::firstWhere('no_rm', $request->norm);
            $pasien->update([
                "no_Bpjs" => $request->nomorkartu,
                "no_tlp" => $request->nohp,
            ]);
            $request['pasienbaru'] = 0;
        }
        $res_antrian = $api->tambah_antrian($request);
        if ($res_antrian->metadata->code == 200) {
            if ($request->statuspasien == "BARU") {
                $request['taskid'] = 1;
                $request['waktu'] = $waktu1;
                $taskid1 = $api->update_antrian($request);
                $request['taskid'] = 2;
                $request['waktu'] = $waktu2;
                $taskid2 = $api->update_antrian($request);
            }
            $request['taskid'] = 3;
            $request['waktu'] = $waktu3;
            $taskid3 = $api->update_antrian($request);
            $antrian->update([
                "nomorkartu" => $request->nomorkartu,
                "nik" => $request->nik,
                "nohp" => $request->nohp,
                "nama" => $pasien->nama_px,
                "norm" => $pasien->no_rm,
                "jampraktek" => $request->jampraktek,
                "jeniskunjungan" => $request->jeniskunjungan,
                "nomorreferensi" => $request->nomorreferensi,
                "jenispasien" => $jenispasien,
                "pasienbaru" => $request->pasienbaru,
                "namapoli" => $request->namapoli,
                "namadokter" => $request->namadokter,
                "taskid" => $request->taskid,
                "keterangan" => $request->keterangan,
                // "user" => Auth::user()->name,
                "status_api" => $request->status_api,
            ]);
            $wa = new WhatsappController();
            $request['message'] = "Pasien antrian atas nama " . $antrian->nama . " dengan kode booking " . $antrian->kodebooking . " telah didaftarkan.\n\n" . $request->keterangan;
            $request['number'] = $antrian->nohp;
            $wa->send_message($request);
            Alert::success('Success', 'Success Message : ' . $request->keterangan);
            return redirect()->back();
        } else {
            Alert::error('Error', 'Error Message : ' . $res_antrian->metadata->message);
            return redirect()->back();
        }
    }
    public function update_pendaftaran_online(Request $request)
    {
        // validation
        $request->validate([
            'antrianidOn' => 'required',
            'statuspasienOn' => 'required',
            'nikOn' => 'required',
            'namaOn' => 'required',
            'nohpOn' => 'required',
            'jeniskelaminOn' => 'required',
            'tanggallahirOn' => 'required',
            // 'alamatOn' => 'required',
            // 'kodepropOn' => 'required',
        ]);
        // init
        $antrian = Antrian::firstWhere('id', $request->antrianidOn);
        // update antrian bpjs
        $request['kodebooking'] = $antrian->kodebooking;
        $request['taskid'] = 3;
        if ($antrian->jenispasien == "JKN") {
            $request['status_api'] = 1;
            $request['keterangan'] = "Untuk pasien JKN silahkan melakukan menunggu di poliklinik untuk dilayani";
        } else {
            $request['status_api'] = 0;
            $request['keterangan'] = "Untuk pasien NON-JKN silahkan melakukan pembayaran pendaftaran ke loket pembayaran";
        }
        $request['waktu'] = Carbon::now()->timestamp * 1000;;
        $vclaim = new AntrianBPJSController();
        $response = $vclaim->update_antrian($request);
        if ($response->metadata->code == 200) {
            // update pasien
            $pasien = PasienDB::firstWhere('nik_bpjs', $request->nikOn);
            $pasien->update(
                [
                    "no_Bpjs" => $request->nomorkartuOn,
                    "nik_bpjs" => $request->nikOn,
                    "no_rm" => $request->normOn,
                    // "nomorkk" => $request->nomorkk,
                    "nama_px" => $request->namaOn,
                    "jenis_kelamin" => $request->jeniskelaminOn,
                    "tgl_lahir" => $request->tanggallahirOn,
                    "no_tlp" => $request->nohpOn,
                    "alamat" => $request->alamatOn,
                    "kode_propinsi" => $request->kodepropOn,
                    // "namaprop" => $request->namaprop,
                    "kode_kabupaten" => $request->kodedati2On,
                    // "namadati2" => $request->namadati2,
                    "kode_kecamatan" => $request->kodekecOn,
                    // "namakec" => $request->namakec,
                    "kode_desa" => $request->kodekelOn,
                    // "namakel" => $request->namakel,
                    // "rw" => $request->rw,
                    // "rt" => $request->rt,
                    // "status" => $request->status,
                ]
            );
            // update antrian simrs
            $antrian->update([
                'taskid' => 3,
                'status_api' => $request->status_api,
                'keterangan' => $request->keterangan,
                // 'user' => Auth::user()->name,
            ]);
            // notif wa
            $wa = new WhatsappController();
            $request['message'] = "Pasien antrian atas nama " . $antrian->nama . " dengan kode booking " . $antrian->kodebooking . " telah didaftarkan.\n\n" . $request->keterangan;
            $request['number'] = $antrian->nohp;
            $wa->send_message($request);
            Alert::success('Success', "Pendaftaran Berhasil. " . $request->keterangan . " " . $response->metadata->message);
            return redirect()->back();
        }
        // jika gagal update antrian bpjs
        else {
            Alert::error('Error', "Pendaftaran Gagal.\n" . $response->metadata->message);
            return redirect()->back();
        }
    }
    public function batal_antrian($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        $request['kodebooking'] = $antrian->kodebooking;
        $request['keterangan'] = "Dibatalkan dari sisi sistem oleh " . Auth::user()->name;
        $vclaim = new AntrianBPJSController();
        $response = $vclaim->batal_antrian($request);
        Alert::success('Success', "Antrian berhasil dibatalkan. " . $response->metadata->message);
        return redirect()->back();
    }
    // kasir
    public function pembayaran(Request $request)
    {
        $antrians = [];
        if ($request->tanggal) {
            $antrians = Antrian::where('taskid', '>=', 3)
                ->where('jenispasien', "NON-JKN")
                ->whereDate('tanggalperiksa', $request->tanggal)
                ->get();
        }
        return view('simrs.antrian_pembayaran', [
            'antrians' => $antrians,
            'request' => $request,
        ]);
    }
    public function update_pembayaran(Request $request)
    {
        $antrian = Antrian::find($request->antrianid);
        $antrian->update([
            "taskid" => 3,
            // "user" => Auth::user()->name,
            "status_api" => 1,
        ]);
        try {
            // notif wa
            $wa = new WhatsappController();
            $request['keterangan'] =  "Silahkan menunggu panggilan di Poliklinik " . $antrian->namapoli;
            $request['message'] =  "Terima kasih anda telah membayar karcis pendaftaran pasien umum atas nama " . $antrian->nama . " dengan kode booking " . $antrian->kodebooking . ". " . $request->keterangan;
            $request['number'] = $antrian->nohp;
            $wa->send_message($request);
        } catch (\Throwable $th) {
            //throw $th;
        }
        Alert::success('Success', 'Pembayaran berhasil diupdate');
        return redirect()->back();
    }
    // poliklinik
    public function poli(Request $request)
    {
        $antrians = null;
        if ($request->tanggal) {
            $antrians = Antrian::whereDate('tanggalperiksa', $request->tanggal)
                ->get();
            if ($request->kodepoli != null) {
                $antrians = $antrians->where('kodepoli', $request->kodepoli);
            }
            if ($request->kodedokter != null) {
                $antrians = $antrians->where('kodedokter', $request->kodedokter);
            }
        }
        $polis = Poliklinik::where('status', 1)->get();
        if ($request->kodepoli == null) {
            $dokters = ParamedisDB::where('kode_dokter_jkn', "!=", null)
                ->where('unit', "!=", null)
                ->get();
        } else {
            $poli =   UnitDB::firstWhere('KDPOLI', $request->kodepoli);
            $dokters = ParamedisDB::where('unit', $poli->kode_unit)
                ->where('kode_dokter_jkn', "!=", null)
                ->get();
        }
        return view('simrs.antrian_poli', [
            'antrians' => $antrians,
            'request' => $request,
            'polis' => $polis,
            'dokters' => $dokters,
        ]);
    }
    public function panggil_poli($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        if ($antrian) {
            $request['kodebooking'] = $antrian->kodebooking;
            $request['taskid'] = 4;
            $request['keterangan'] = "Panggilan ke poliklinik yang anda pilih";
            $request['waktu'] = Carbon::now()->timestamp * 1000;
            $vclaim = new AntrianBPJSController();
            $response = $vclaim->update_antrian($request);
            // try {
            //     // notif wa
            //     $wa = new WhatsappController();
            //     $request['message'] = "Panggilan antrian atas nama pasien " . $antrian->nama . " dengan nomor antrean " . $antrian->nomorantrean . " untuk segera dilayani di POLIKLINIK " . $antrian->namapoli;
            //     $request['number'] = $antrian->nohp;
            //     $wa->send_message($request);
            // } catch (\Throwable $th) {
            //     //throw $th;
            // }
            $antrian->update([
                'taskid' => $request->taskid,
                'status_api' => 1,
                'keterangan' => $request->keterangan,
                // 'user' => Auth::user()->name,
            ]);
            Alert::success('Success', 'Panggilan Berhasil ' . $response->metadata->message);
            return redirect()->back();
        } else {
            Alert::error('Error', 'Kodebooking tidak ditemukan');
            return redirect()->back();
        }
    }
    public function edit($id)
    {
        $antrian = Antrian::find($id);
        return response()->json($antrian);
    }
    public function lanjut_farmasi($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        $request['kodebooking'] = $antrian->kodebooking;
        $request['taskid'] = 5;
        $request['keterangan'] = "Silahkan tunggu di farmasi untuk pengambilan obat.";
        $request['waktu'] = Carbon::now()->timestamp * 1000;
        $vclaim = new AntrianBPJSController();
        $response = $vclaim->update_antrian($request);
        $antrian->update([
            'taskid' => $request->taskid,
            'status_api' => 0,
            'keterangan' => $request->keterangan,
            // 'user' => Auth::user()->name,
        ]);
        // try {
        //     // notif wa
        //     $wa = new WhatsappController();
        //     $request['message'] = "Pelayanan di poliklinik atas nama pasien " . $antrian->nama . " dengan nomor antrean " . $antrian->nomorantrean . " telah selesai. " . $request->keterangan;
        //     $request['number'] = $antrian->nohp;
        //     $wa->send_message($request);
        // } catch (\Throwable $th) {
        //     //throw $th;
        // }
        Alert::success('Success', "Antrian Berhasil Dilanjutkan ke Farmasi.\n" . $response->metadata->message);
        return redirect()->back();
    }
    public function selesai($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        $request['kodebooking'] = $antrian->kodebooking;
        $request['taskid'] = 5;
        $request['keterangan'] = "Semoga cepat sembuh";
        $request['waktu'] = Carbon::now()->timestamp * 1000;
        $vclaim = new AntrianBPJSController();
        $response = $vclaim->update_antrian($request);
        $antrian->update([
            'taskid' => $request->taskid,
            'status_api' => 1,
            'keterangan' => $request->keterangan,
            // 'user' => Auth::user()->name,
        ]);
        // try {
        //     // notif wa
        //     $wa = new WhatsappController();
        //     $request['message'] = "Pelayanan di poliklinik atas nama pasien " . $antrian->nama . " dengan nomor antrean " . $antrian->nomorantrean . " telah selesai. " . $request->keterangan;
        //     $request['number'] = $antrian->nohp;
        //     $wa->send_message($request);
        // } catch (\Throwable $th) {
        //     //throw $th;
        // }
        Alert::success('Success', "Antrian Selesai. Semoga cepat sembuh.\n" . $response->metadata->message);
        return redirect()->back();
    }
    public function surat_kontrol_poli(Request $request)
    {
        $kunjungans = null;
        $surat_kontrols = null;
        if ($request->tanggal) {
            $surat_kontrols = SuratKontrol::whereDate('tglTerbitKontrol', $request->tanggal)->get();
            $kunjungans = KunjunganDB::whereDate('tgl_masuk', $request->tanggal)
                ->where('no_sep', "!=", '')
                ->where('no_sep', "!=", null)
                ->where('status_kunjungan', "!=", 8)
                ->where('kode_unit', "!=", null)
                ->get();
            if ($request->kodepoli != null) {
                $poli = UnitDB::where('KDPOLI', $request->kodepoli)->first();
                $kunjungans = $kunjungans->where('kode_unit', $poli->kode_unit);
                $surat_kontrols = $surat_kontrols->where('poliTujuan', $request->kodepoli);
            }
            if ($request->kodedokter != null) {
                $dokter = ParamedisDB::where('kode_dokter_jkn', $request->kodedokter)->first();
                $kunjungans = $kunjungans->where('kode_paramedis', $dokter->kode_paramedis);
            }
        }
        if ($request->kodepoli == null) {
            $unit = UnitDB::where('KDPOLI', "!=", null)->get();
            $dokters = ParamedisDB::where('kode_dokter_jkn', "!=", null)
                ->where('unit', "!=", null)
                ->get();
        } else {
            $unit = UnitDB::where('KDPOLI', "!=", null)->get();
            $poli =   UnitDB::firstWhere('KDPOLI', $request->kodepoli);
            $dokters = ParamedisDB::where('unit', $poli->kode_unit)
                ->where('kode_dokter_jkn', "!=", null)
                ->get();
        }

        return view('simrs.antrian_surat_kontrol_poli', [
            'kunjungans' => $kunjungans,
            'request' => $request,
            'unit' => $unit,
            'dokters' => $dokters,
            'surat_kontrols' => $surat_kontrols,
        ]);
    }
    // public function surat_kontrol_create(Request $request)
    // {
    //     dd($request->all());
    // }
    // farmasi
    public function farmasi(Request $request)
    {
        $antrians = null;
        if ($request->tanggal) {
            $request['tanggal'] = Carbon::now()->format('Y-m-d');
            $antrians = Antrian::whereDate('tanggalperiksa', $request->tanggal)
                ->where('taskid', '>=', 3)->get();
        }
        // $polis = Poliklinik::where('status', 1)->get();
        // $dokters = Dokter::get();
        return view('simrs.antrian_farmasi', [
            'antrians' => $antrians,
            'request' => $request,
            // 'polis' => $polis,
            // 'dokters' => $dokters,
        ]);
    }
    public function racik_farmasi($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        if ($antrian) {
            $request['kodebooking'] = $antrian->kodebooking;
            $request['taskid'] = 6;
            $request['keterangan'] = "Proses peracikan obat";
            $request['waktu'] = Carbon::now()->timestamp * 1000;
            $vclaim = new AntrianBPJSController();
            $response = $vclaim->update_antrian($request);
            $antrian->update([
                'taskid' => $request->taskid,
                'status_api' => 1,
                'keterangan' => $request->keterangan,
                // 'user' => Auth::user()->name,
            ]);
            try {
                // notif wa
                $wa = new WhatsappController();
                $request['message'] = "Resep obat atas nama pasien " . $antrian->nama . " dengan nomor antrean " . $antrian->nomorantrean . " telah diterima farmasi. Silahkan menunggu peracikan obat.";
                $request['number'] = $antrian->nohp;
                $wa->send_message($request);
            } catch (\Throwable $th) {
                //throw $th;
            }
            Alert::success('Proses', 'Proses Peracikan Obat ' . $response->metadata->message);
            return redirect()->back();
        } else {
            Alert::error('Error', 'Kodebooking tidak ditemukan');
            return redirect()->back();
        }
    }
    public function selesai_farmasi($kodebooking, Request $request)
    {
        $antrian = Antrian::where('kodebooking', $kodebooking)->first();
        $request['kodebooking'] = $antrian->kodebooking;
        $request['taskid'] = 7;
        $request['keterangan'] = "Selesai peracikan obat";
        $request['waktu'] = Carbon::now()->timestamp * 1000;
        $vclaim = new AntrianBPJSController();
        $response = $vclaim->update_antrian($request);
        $antrian->update([
            'taskid' => $request->taskid,
            'status_api' => 1,
            'keterangan' => $request->keterangan,
            // 'user' => Auth::user()->name,
        ]);
        try {
            // notif wa
            $wa = new WhatsappController();
            $request['message'] = "Resep obat atas nama pasien " . $antrian->nama . " dengan nomor antrean " . $antrian->nomorantrean . " telah telah selesai diracik. Silahkan diambil di farmasi.";
            $request['number'] = $antrian->nohp;
            $wa->send_message($request);
        } catch (\Throwable $th) {
            //throw $th;
        }
        Alert::success('Success', 'Selesai Peracikan Obat ' . $response->metadata->message);
        return redirect()->back();
    }
    // farmasi
    public function show($kodebooking, Request $request)
    {
        dd($request->all());
        $antrian = Antrian::firstWhere('kodebooking', $kodebooking);
        $poli = Poliklinik::get();
        return view('simrs.antrian_baru_offline', [
            'poli' => $poli,
            'antrian' => $antrian,
        ]);
    }
    public function display_pendaftaran(Request $request)
    {
        $poliklinik = Poliklinik::with(['antrians'])->where('status', 1)->get();
        return view('simrs.display_pendaftaran', [
            'poliklinik' => $poliklinik,
            'request' => $request,
        ]);
    }
    public function store(Request $request)
    {
        $request->validate([
            'nik' => 'required',
            'nohp' => 'required',
            'jeniskunjungan' => 'required',
            'tanggalperiksa' => 'required',
            'kodepoli' => 'required',
            'kodedokter' => 'required',
        ]);
        $api = new AntrianBPJSController();
        $response = $api->ambil_antrian($request);
        $response = json_decode(json_encode($response, true));
        if ($response->metadata->code == 200) {
            Alert::success('Success Title', 'Success Message');
            return redirect()->route('antrian.tambah');
        } else {
            Alert::error('Error Title', "Error Message " . $response->metadata->message);
            return redirect()->route('antrian.tambah');
        }
    }
    // admin pendaftaran
    public function laporan(Request $request)
    {
        if ($request->tanggal == null) {
            $tanggal_awal = Carbon::now()->startOfMonth()->format('Y-m-d');
            $tanggal_akhir = Carbon::now()->endOfMonth()->format('Y-m-d');
        } else {
            $tanggal = explode(' - ', $request->tanggal);
            $tanggal_awal = Carbon::parse($tanggal[0])->format('Y-m-d');
            $tanggal_akhir = Carbon::parse($tanggal[1])->format('Y-m-d');
        }
        $antrians = Antrian::whereBetween('tanggalperiksa', [$tanggal_awal, $tanggal_akhir])
            ->get();
        return view('simrs.antrian_laporan', [
            'antrians' => $antrians,
            'request' => $request,
        ]);
    }
    public function laporan_tanggal(Request $request)
    {
        if ($request['tanggal'] == null) {
            $request['tanggal'] = Carbon::now()->format('Y-m-d');
            $request['waktu'] = 'rs';
            $antrians = null;
            return view('simrs.antrian_laporan_tanggal', [
                'antrians' => $antrians,
                'request' => $request,
            ]);
        } else {
            $api = new AntrianBPJSController();
            $response = $api->dashboard_tanggal($request);
            if ($response->metadata->code == 200) {
                $antrians = $response->response->list;
                Alert::success('Success', "Success Message " . $response->metadata->message);
                return view('simrs.antrian_laporan_tanggal', [
                    'antrians' => $antrians,
                    'request' => $request,
                ]);
            } else {
                Alert::error('Error Title', "Error Message " . $response->metadata->message);
                return redirect()->route('antrian.laporan_tanggal');
            }
        }
    }
    public function laporan_bulan(Request $request)
    {
        if ($request['tanggal'] == null) {
            $request['tanggal'] = Carbon::now()->format('Y-m');
            $request['tahun'] = Carbon::now()->format('Y');
            $request['bulan'] = Carbon::now()->format('m');
            $request['waktu'] = 'rs';
            $antrians = null;
            return view('simrs.antrian_laporan_bulan', [
                'antrians' => $antrians,
                'request' => $request,
            ]);
        } else {
            $tanggal = explode('-', $request->tanggal);
            $request['tahun'] = $tanggal[0];
            $request['bulan'] = $tanggal[1];
            $api = new AntrianBPJSController();
            $response = $api->dashboard_bulan($request);
            if ($response->metadata->code == 200) {
                Alert::success('Success', "Success Message " . $response->metadata->message);
                $antrians = $response->response->list;
                return view('simrs.antrian_laporan_bulan', [
                    'antrians' => $antrians,
                    'request' => $request,
                ]);
            } else {
                Alert::error('Error Title', "Error Message " . $response->metadata->message);
                return redirect()->route('antrian.laporan_bulan');
            }
        }
    }
}
