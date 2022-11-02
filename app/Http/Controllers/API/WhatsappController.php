<?php

namespace App\Http\Controllers\API;

use App\Models\AntrianDB;
use App\Models\JadwalDokter;
use App\Models\JadwalLiburPoliDB;
use App\Models\PasienDB;
use App\Models\Poliklinik;
use App\Models\PoliklinikDB;
use App\Models\UnitDB;
use Carbon\Carbon;
use GuzzleHttp\Client;
use Illuminate\Contracts\Support\Renderable;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Http;
use SebastianBergmann\CodeCoverage\Report\Xml\Unit;
use Image;
use SimpleSoftwareIO\QrCode\Facades\QrCode;

class WhatsappController extends Controller
{
    public $hari = ["MINGGU", "SENIN", "SELASA", "RABU", "KAMIS", "JUMAT", "SABTU"];
    protected $except = [
        'callback',
    ];
    public function index(Request $request)
    {
        $request['message']  = "Rawat Inap BEDAH Dr. MOHAMAD ROMDHONI_SURATKONTROL#1018R0010922K006951#521#2022-10-05";
        $request['number'] = '6289529909036@c.us';
        $sk = $this->callback($request);
        dd('callback');

        // $request['kodebooking'] = "63300BAABB42A";
        // $antrian = new AntrianBPJSController();
        // $antrian->print_ulang($request);
        // return $this->surat_kontrol_peserta($pesan, $request);
    }
    public function send_message(Request $request)
    {
        $url = env('WHATASAPP_URL') . "send-message";
        $response = Http::post($url, [
            'number' => $request->number,
            'message' => $request->message,
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function send_notif(Request $request)
    {
        $url = env('WHATASAPP_URL') . "notif";
        $response = Http::post($url, [
            'message' => $request->notif,
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function send_button(Request $request)
    {
        $url = env('WHATASAPP_URL') . "send-button";
        $response = Http::post($url, [
            'number' => $request->number,
            'contenttext' => $request->contenttext,
            'footertext' => $request->footertext,
            'titletext' => $request->titletext,
            'buttontext' => $request->buttontext, // 'UMUM,BPJS'
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function send_list(Request $request)
    {
        $url = env('WHATASAPP_URL') . "send-list";
        $response = Http::post($url, [
            'number' => $request->number,
            'contenttext' => $request->contenttext,
            'footertext' => $request->footertext,
            'titletext' => $request->titletext,
            'buttontext' => $request->buttontext, #wajib
            'titlesection' => $request->titlesection,
            'rowtitle' => $request->rowtitle, #wajib
            'rowdescription' => $request->rowdescription,
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function send_image(Request $request)
    {
        $url = env('WHATASAPP_URL') . "send-media";
        $response = Http::post($url, [
            'number' => $request->number,
            'fileurl' => $request->fileurl,
            'caption' => $request->caption,
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function send_filepath(Request $request)
    {
        $url = env('WHATASAPP_URL') . "send-filepath";
        $response = Http::post($url, [
            'number' => $request->number,
            'filepath' => $request->filepath,
            'caption' => $request->caption,
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function callback(Request $request)
    {
        $pesan = strtoupper($request->message);
        switch ($pesan) {
            case 'NOTIF':
                $request['notif'] = "Test Send Notif";
                return $this->send_notif($request);
                break;
            case 'MESSAGE':
                $request['message'] = "Test Send Message";
                return $this->send_message($request);
                break;
            case 'BUTTON':
                $request['contenttext'] = "contenttext";
                $request['footertext'] = 'footertext';
                $request['buttontext'] = 'buttontext1,buttontext2,buttontext3';
                return $this->send_button($request);
                break;
            case 'LIST':
                $request['contenttext'] = "contenttext";
                $request['titletext'] = "titletext";
                $request['buttontext'] = 'buttontext';
                $request['rowtitle'] = 'rowtitle1,rowtitle2,rowtitle3';
                $request['rowdescription'] = 'rowdescription1,rowdescription2,rowdescription3';
                return $this->send_list($request);
                break;
            case 'INFO CARA PENDAFTARAN':
                $request['message'] = "Untuk pendaftaran melalui Layanan Whatsapp RSUD Waled sebagai berikut :\n\n1. Klik *MENU UTAMA* pilih *DAFTAR PASIEN RAWAT JALAN*. \n2. Pilih *POLIKLINIK* yang akan dikunjungi dan yang tersedia untuk daftar online. \n3. Pilih *TANGGAL* kapan pasien akan berkunjung. \n4. Pilih *JADWAL DOKTER* yang akan dituju oleh pasien. \n5. Pilih *JENIS PASIEN* terdapat pilihan pasien *JKN / UMUM*. \n6. Menuliskan format pendaftaran, untuk *PASIEN JKN* memasukan *Nomor Kartu* JKN/BPJS/KIS, untuk *PASIEN UMUM* memasukan *NIK/KTP*. \n7. Jika *PASIEN JKN/BPJS* akan memilih jenis kunjungan melalui Rujukan Faskes 1, Kontrol, atau Rujukan Antar RS. Kemudian pilih nomor rujukan/surat tersebut. \n8. Konfirmasi pendaftaran lalu berhasil didaftarkan atau batal pendaftaran. Anda akan mendapatkan gambar *QR Code* untuk discan saat checkin di Rumah Sakit.\n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
                return $this->send_message($request);
                break;
            case 'INFO JADWAL POLIKLINIK':
                $request['contenttext'] = "Link Jadwal Dokter Poliklinik : \nhttp://sim.rsudwaled.id/antrian/info_jadwaldokter \n\nLink Jadwal Libur Poliklinik : \nhttp://sim.rsudwaled.id/antrian/info_jadwallibur \n\nSilahkan pilih poliklinik yang tersedia untuk daftar online rawat jalan pasien dibawah ini.";
                $request['titletext'] = "Info Jadwal Dokter Poliklinik 🧑🏻‍⚕🏥";
                $request['buttontext'] = 'PILIH POLIKLINIK';
                $rowpoli = null;
                $poliklinik = PoliklinikDB::where('status', 1)->get('namasubspesialis');
                foreach ($poliklinik as  $value) {
                    $rowpoli =  $rowpoli . 'JADWAL_POLIKLINIK_' . $value->namasubspesialis  . ',';
                }
                $request['rowtitle'] = $rowpoli;
                return $this->send_list($request);
            case 'DAFTAR PASIEN RAWAT JALAN':
                // if ($request->number == "6289529909036@c.us") {
                $this->pilih_poli($pesan, $request);
                // } else {
                // $request['message'] = "Mohon maaf server BPJS sedang dalam perbaikan (201)";
                // $this->send_message($request);
                // }
                break;
            default:
                // info jadwal poli
                if (str_contains($pesan, 'JADWAL_POLIKLINIK_')) {
                    $poli = explode('_', $pesan)[2];
                    $rowjadwaldokter = null;
                    $jadwaldokters = JadwalDokter::where('namasubspesialis', $poli)->get();
                    foreach ($jadwaldokters as  $value) {
                        $rowjadwaldokter = $rowjadwaldokter . $this->hari[$value->hari] . '  : ' . $value->namadokter . ' ' . $value->jadwal . " KUOTA : " . $value->kapasitaspasien . "\n";
                    }
                    $request['contenttext'] = "Jadwal dokter poliklinik " . $poli . " sebagai berikut : \n\n" . $rowjadwaldokter;
                    $request['titletext'] = "3. Pilih Jadwal Dokter " . $poli;
                    $request['buttontext'] = 'INFO JADWAL POLIKLINIK';
                    return $this->send_button($request);
                }
                // 2. pilih poli terus tanggal
                else if (substr($pesan, 0, 11) == 'POLIKLINIK_') {
                    $poli = explode('_', $pesan)[1];
                    $now = Carbon::now();
                    $rowtanggal = 'TANGGAL_' . $now->format('Y-m-d') . "#" . $poli;
                    for ($i = 0; $i < 6; $i++) {
                        $rowtanggal = $rowtanggal . ',' .  'TANGGAL_' . $now->addDay(1)->format('Y-m-d') . "#" . $poli;
                    }
                    $request['contenttext'] = "Silahkan pilih tanggal kunjungan rawat jalan Poliklinik _" . strtoupper($poli) . "_ dibawah ini.";
                    $request['titletext'] = "2. Pilih Tanggal Kunjungan 🗓";
                    $request['buttontext'] = 'PILIH TANGGAL';
                    $request['rowtitle'] = $rowtanggal;
                    return $this->send_list($request);
                }
                // 3. tanggal poli terus pilih jadwal
                else if (str_contains($pesan, 'TANGGAL_')) {
                    $format = explode('_', $pesan)[1];
                    $tanggal = Carbon::parse(explode('#', $format)[0]);
                    $poli = explode('#', $format)[1];
                    $hari = $tanggal->dayOfWeek;
                    $rowjadwaldokter = null;
                    $jadwaldokters = JadwalDokter::where('hari', $hari)
                        ->where('namasubspesialis', $poli)->get();
                    if ($jadwaldokters->count() == 0) {
                        $request['contenttext'] = "Mohon maaf *Tidak Ada Jadwal Dokter* di Poliklinik _" . $poli . "_ pada tanggal " . $tanggal->format('Y-m-d') . " ❎🙏\n\nSilahkan pilih jadwal dokter poliklinik pada tanggal yang berbeda dibawah ini.";
                        $request['titletext'] = "2. Pilih Tanggal Lain Kunjungan 🗓";
                        $request['buttontext'] = 'PILIH TANGGAL';
                        $now = Carbon::now();
                        $rowhari = 'TANGGAL_' . $now->format('Y-m-d') . "#" . $poli;
                        for ($i = 0; $i < 6; $i++) {
                            $rowhari = $rowhari . ','  . 'TANGGAL_' . $now->addDay(1)->format('Y-m-d') .  "#" . $poli;
                        }
                        $request['rowtitle'] = $rowhari;
                        return $this->send_list($request);
                    }
                    foreach ($jadwaldokters as  $value) {
                        $rowjadwaldokter = $rowjadwaldokter . $value->jadwal . " Dr." . $value->namadokter . ' _JADWAL.ID#' . $value->id . '#' . $tanggal->format('Y-m-d') . ',';
                    }
                    $request['contenttext'] = "Silahkan pilih jadwal dokter Poliklinik _" . $poli . "_ pada tanggal " . $tanggal->format('Y-m-d') . " dibawah ini.";
                    $request['titletext'] = "3. Pilih Jadwal Dokter 🧑🏻‍⚕";
                    $request['buttontext'] = 'PILIH JADWAL DOKTER';
                    $request['rowtitle'] = $rowjadwaldokter;
                    return $this->send_list($request);
                }
                // 4. pilih dokter terus jenis pasien
                else if (str_contains($pesan, '_JADWAL.ID#')) {
                    $jadwalid = explode('#', $pesan)[1];
                    $tanggal = explode('#', $pesan)[2];
                    $jadwaldokter = JadwalDokter::find($jadwalid);
                    // jika jadwal libur
                    if ($jadwaldokter->libur == 1) {
                        $poli = $jadwaldokter->namasubspesialis;
                        $now = Carbon::now();
                        $request['notif'] = '4 cek jadwal libur poli ' . $poli . " tanggal " . $tanggal;
                        $this->send_notif($request);
                        $rowtanggal = 'TANGGAL_' . $now->format('Y-m-d') . "#" . $poli;
                        for ($i = 0; $i < 6; $i++) {
                            $rowtanggal = $rowtanggal . ',' . 'TANGGAL_' . $now->addDay(1)->format('Y-m-d') . "#" . $poli;
                        }
                        $request['contenttext'] = "Silahkan pilih tanggal lain rawat jalan poliklinik " . strtoupper($poli) . " dibawah ini.";
                        $request['titletext'] = "Jadwal Dokter Pilihan sedang Libur/Tutup";
                        $request['buttontext'] = 'PILIH TANGGAL';
                        $request['rowtitle'] = $rowtanggal;
                        return $this->send_list($request);
                    }
                    // jika jadwal jalan
                    else {
                        $request['titletext'] = "4. Pilih Jenis Pasien 😷";
                        $request['contenttext'] = "Jadwal dokter poliklinik yang anda pilih adalah sebagai berikut :\n\n*Poliklinik* : " . strtoupper($jadwaldokter->namasubspesialis) . "\n*Dokter* :  " . $jadwaldokter->namadokter . "\n*Jam Praktek* : " . $jadwaldokter->jadwal . "\n*Tanggal Periksa* :  " . $tanggal . "\n\nSilahakan pilih jenis pasien yang akan didaftarkan ini. \n\nCatatan :\nPasien JKN/BPJS : diharuskan memiliki rujukan faskes 1 yang masih aktif, atau Surat Kontol Poliklinik.\nPasien UMUM : hanya pasien umum yang telah terdaftar saja dapat melakukan daftar online. Bagi yang belum terdaftar silahkan daftar langsung ditempat";
                        $request['buttontext'] = 'PASIEN BPJS_' . $jadwalid . '#' . $tanggal . ',PASIEN UMUM_' . $jadwalid . '#' . $tanggal;
                        return $this->send_button($request);
                    }
                }
                // 5. pilih jenis pasien, masukan rujukan
                else if (substr($pesan, 0, 12) ==  'PASIEN BPJS_') {
                    $jadwalid = explode('_', $pesan)[1];
                    $request['message'] = "*5. Ketik Format Pasien BPJS*\nUntuk pasien JKN/BPJS silahkan ketik nomor kartu 13 digit yang tertera pada kartu bpjs anda dengan format seperti berikut : \n\n_*Nomor Kartu*_#BPJS#" . $jadwalid . "\n(Contoh)\n0000067XX23XX#BPJS#" . $jadwalid;
                    $this->send_message($request);
                    $request['message'] = "0000067XX23XX#BPJS#" . $jadwalid;
                    return $this->send_message($request);
                }
                // 5. pilih jenis pasien, masukan nik
                else if (substr($pesan, 0, 12) == 'PASIEN UMUM_') {
                    $jadwalid = explode('_', $pesan)[1];
                    $request['message'] = "*5. Ketik Format Pasien Umum*\nUntuk pasien UMUM silahkan ketik nomor nik/ktp 16 digit yang tertera pada Kartu Tanda Penduduk (KTP) anda dengan format seperti berikut : \n\n_*NIK / KTP*_#UMUM#" . $jadwalid . "\n\n(Contoh)\n3209XXXX1234XXXX#UMUM#" . $jadwalid;
                    $this->send_message($request);
                    $request['message'] = "3209XXXX1234XXXX#UMUM#" . $jadwalid;
                    return $this->send_message($request);
                }
                // 6. cek pasien umum
                else if (str_contains($pesan, '#UMUM#')) {
                    return $this->konfirmasi_antrian_umum($pesan, $request);
                }
                // 6. pilih jenis kunjungan untuk pasien bpjs
                else if (str_contains($pesan, '#BPJS#')) {
                    return $this->cek_nomorkartu_peserta($pesan, $request);
                }
                // 7. pilih jenis pasien, masukan nik
                else if (str_contains($pesan, '#DAFTAR_UMUM#')) {
                    return $this->daftar_antrian_umum($pesan, $request);
                }
                // 7. pilih rujukan faskses 1 peserta
                else if (substr($pesan, 0, 17) == 'RUJUKAN FASKES 1_') {
                    return $this->rujukan_peserta($pesan, $request);
                }
                // 7. pilih rujukan faskses 1 peserta
                else if (substr($pesan, 0, 8) == 'KONTROL_') {
                    return $this->surat_kontrol_peserta($pesan, $request);
                }
                // 7. pilih rujukan faskses 1 peserta
                else if (substr($pesan, 0, 17) == 'RUJUKAN ANTAR RS_') {
                    return $this->rujukan_rs_peserta($pesan, $request);
                }
                // 8. pilih rujukan faskses 1 peserta
                else if (str_contains($pesan, '_RUJUKANFKTP#')) {
                    return $this->cek_rujukan($pesan, $request);
                }
                // 8. pilih suratkontrol , kemudian cek
                else if (str_contains($pesan, '_SURATKONTROL#')) {
                    return $this->cek_surat_kontrol($pesan, $request);
                }
                // 8. pilih rujukan faskses 1 peserta
                else if (str_contains($pesan, '_RUJUKANRS#')) {
                    return $this->cek_rujukan_rs($pesan, $request);
                }
                // 9. insert antrian rujukan fk1
                else if (substr($pesan, 0, 20) == 'DAFTAR RUJUKAN FKTP_') {
                    return $this->daftar_rujukan_fktp($pesan, $request);
                }
                // 9. insert antrian surat rujukan
                else if (substr($pesan, 0, 15) == 'DAFTAR KONTROL_') {
                    return $this->daftar_surat_kontrol($pesan, $request);
                }
                // 9. insert antrian rujukan rs
                else if (substr($pesan, 0, 18) == 'DAFTAR RUJUKAN RS_') {
                    return $this->daftar_rujukan_rs($pesan, $request);
                }
                // default
                else {
                    $request['contenttext'] = "Mohon maaf pesan yang anda kirim tidak dapat diproses oleh sistem ❎🙏\n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*\n\nSilahkan klik *MENU UTAMA* yang dapat diproses dibawah ini ⬇";
                    $request['titletext'] = "Layanan Whatsapp RSUD Waled 📱🏥";
                    $request['buttontext'] = 'MENU UTAMA';
                    $request['rowtitle'] = 'INFO CARA PENDAFTARAN,DAFTAR PASIEN RAWAT JALAN,INFO JADWAL POLIKLINIK,PERTANYAAN DAN PENGADUAN';
                    return $this->send_list($request);
                    break;
                }
        }
    }
    public function pilih_poli($pesan, Request $request)
    {
        $request['contenttext'] = "Silahkan pilih poliklinik yang tersedia untuk daftar online rawat jalan pasien dibawah ini.";
        $request['titletext'] = "1. Pilih Poliklinik Rawat Jalan 🏥";
        $request['buttontext'] = 'PILIH POLIKLINIK';
        $rowpoli = null;
        $poliklinik = PoliklinikDB::where('status', 1)->get('namasubspesialis');
        foreach ($poliklinik as  $value) {
            $rowpoli =  $rowpoli . 'POLIKLINIK_' . $value->namasubspesialis  . ',';
        }
        $request['rowtitle'] = $rowpoli;
        return $this->send_list($request);
    }
    public function konfirmasi_antrian_umum($pesan, Request $request)
    {
        // init
        try {
            $request['nik'] = explode('#', $pesan)[0];
            $jadwalid = explode('#', $pesan)[2];
            $tanggalperiksa = explode('#', $pesan)[3];
            $jadwaldokter = JadwalDokter::find($jadwalid);
        } catch (\Throwable $th) {
            $request['notif'] = '6 cek umum error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "Error format pendaftaran : " . $th->getMessage() . "\nLihat dan sesuaikan kembali format pendaftaran pasien jkn. \n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $peserta =  $vclaim->peserta_nik($request);
        // berhasil
        if ($peserta->metaData->code == 200) {
            // pasien lama
            if (isset($peserta->response->peserta->mr->noMR)) {
                try {
                    $request['nomorkartu'] = $peserta->response->peserta->noKartu;
                    $request['nama'] = $peserta->response->peserta->nama;
                    $request['nik'] = $peserta->response->peserta->nik;
                    $request['norm'] = $peserta->response->peserta->mr->noMR;
                    $request['status'] = $peserta->response->peserta->statusPeserta->keterangan;
                    $request['nohp'] = $request->number;
                    $request['tanggalperiksa'] = $tanggalperiksa;
                    $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                    $request['kodedokter'] = $jadwaldokter->kodedokter;
                    $request['jampraktek'] = $jadwaldokter->jadwal;
                    $request['jeniskunjungan'] = 3;
                    $request['titletext'] = "6. Konfirmasi Pendaftaran Pasien UMUM / NON-JKN";
                    $request['contenttext'] = "Jadwal dokter poliklinik yang dipilih sebagai berikut :\n\n*Poliklinik* : " . strtoupper($jadwaldokter->namasubspesialis) . "\n*Dokter* :  " . $jadwaldokter->namadokter . "\n*Jam Praktek* : " . $jadwaldokter->jadwal . "\n*Tanggal Periksa* :  " . $tanggalperiksa . "\n\n*Nama Pasien* : " . $request->nama . "\n*Status* : *" . $request->status . "*\n*NIK* : " . $request->nik . "\n*No BPJS* : " . $request->nomorkartu . "\n*No RM* : " . $request->norm .  "\n\nSebagai konfirmasi bahwa data yang diatas adalah benar pasien yang akan didaftarkan. Silahakan pilih tombol dibawah ini.";
                    $request['buttontext'] =  $request->nik . "#DAFTAR_UMUM#" . $jadwalid . "#" . $request->tanggalperiksa;
                    return $this->send_button($request);
                } catch (\Throwable $th) {
                    $request['notif'] = '6 cek umum error : ' . $th->getMessage();
                    $this->send_notif($request);
                    $request['message'] = "6. Cek Peserta Error : " . $th->getMessage();
                    return $this->send_message($request);
                }
            }
            // pasien baru
            else {
                $request['notif'] = "6 cek umum error " . $request->nik . " error : belum memiliki RM";
                $this->send_notif($request);
                $request['message'] = "Error : Mohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                return $this->send_message($request);
            }
        }
        // gagal
        else {
            $request['notif'] = '6 cek umum error : ' . $peserta->metaData->message;
            $this->send_notif($request);
            $request['message'] = "Error format pendaftaran : " . $peserta->metaData->message . "\nLihat dan sesuaikan kembali format pendaftaran pasien umum.\n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
            return $this->send_message($request);
        }
    }
    public function daftar_antrian_umum($pesan, Request $request)
    {
        // init
        try {
            $request['nik'] = explode('#', $pesan)[0];
            $tipepasien = "NON-JKN";
            $jadwalid = explode('#', $pesan)[2];
            $tanggalperiksa = explode('#', $pesan)[3];
            $jadwaldokter = JadwalDokter::find($jadwalid);
        } catch (\Throwable $th) {
            $request['notif'] = '7 daftar umum error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "Error format pendaftaran : " . $th->getMessage() . "\nLihat dan sesuaikan kembali format pendaftaran pasien jkn. \n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $peserta =  $vclaim->peserta_nik($request);
        // berhasil
        if ($peserta->metaData->code == 200) {
            // pasien lama
            if (isset($peserta->response->peserta->mr->noMR)) {
                try {
                    $request['nomorkartu'] = $peserta->response->peserta->noKartu;
                    $request['nama'] = $peserta->response->peserta->nama;
                    $request['nik'] = $peserta->response->peserta->nik;
                    $request['norm'] = $peserta->response->peserta->mr->noMR;
                    $request['status'] = $peserta->response->peserta->statusPeserta->keterangan;
                    // $request['diagnosa'] = $peserta->response->diagnosa->nama;
                    // $request['polirujukan'] = $peserta->response->poliRujukan->nama;
                    $request['nohp'] = $request->number;
                    $request['tanggalperiksa'] = $tanggalperiksa;
                    $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                    $request['kodedokter'] = $jadwaldokter->kodedokter;
                    $request['jampraktek'] = $jadwaldokter->jadwal;
                    $request['jeniskunjungan'] = 3;
                    $antrian = new AntrianBPJSController();
                    $response = json_decode(json_encode($antrian->ambil_antrian($request)));
                    if ($response->metadata->code != 200) {
                        $request['notif'] = '7 daftar umum error : ' . $response->metadata->message;
                        $this->send_notif($request);
                        $request['message'] = "Maaf anda tidak bisa daftar : " .  $response->metadata->message . ". Silahkan daftar melalui offline.";
                        return $this->send_message($request);
                    } else {
                        return $response;
                    }
                } catch (\Throwable $th) {
                    $request['message'] = "Error : " . $th;
                    return $this->send_message($request);
                }
            }
            // pasien baru
            else {
                $request['notif'] = "7 daftar umum " . $request->nik . " error : belum memiliki RM";
                $this->send_notif($request);
                $request['message'] = "Error : Mohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                return $this->send_message($request);
            }
        }
        // gagal
        else {
            $request['notif'] = '7 daftar umum error : ' . $peserta->metaData->message;
            $this->send_notif($request);
            $request['message'] = "Error format pendaftaran : " . $peserta->metaData->message . "\nLihat dan sesuaikan kembali format pendaftaran pasien umum.\n\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
            return $this->send_message($request);
        }
    }
    public function cek_nomorkartu_peserta($pesan, Request $request)
    {

        try {
            $nomorkartu = explode('#', $pesan)[0];
            $format = explode('#', $pesan)[1];
            $jadwal = explode('#', $pesan)[2];
            $tanggalperiksa = explode('#', $pesan)[3];
            $vclaim = new VclaimBPJSController();
            $request['nomorkartu'] = $nomorkartu;
        } catch (\Throwable $th) {
            $request['notif'] = "6 cek nomor kartu " . $nomorkartu . " error : "  . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*6. Cek Nomor Kartu Tidak Bisa*\n" . $th->getMessage();
            return $this->send_message($request);
        }
        $peserta = $vclaim->peserta_nomorkartu($request);
        // gagal peserta
        if ($peserta->metaData->code != 200) {
            $request['notif'] = "6 cek nomor kartu " . $nomorkartu . " error : " . $peserta->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*6. Pilih Jenis Kunjungan*\nMohon maaf " . $peserta->metaData->message;
            return $this->send_message($request);
        }
        // berhasil peserta
        else {
            $peserta = $peserta->response->peserta;
            $request['contenttext'] = "Nomor kartu berhasil ditemukan dengan data sebagai berikut : \n*Nama* : " . $peserta->nama . "\n*NIK* : " . $peserta->nik . "\n*No Kartu* : " . $peserta->noKartu . "\n*No RM* : " . $peserta->mr->noMR . "\n\n*Status* : " . $peserta->statusPeserta->keterangan . "\n*Faskes 1* : " . $peserta->provUmum->nmProvider . "\n*Jenis Peserta* : " . $peserta->jenisPeserta->keterangan . "\n*Hak Kelas* : " . $peserta->hakKelas->keterangan . "\n\nSilahkan pilih jenis kunjungan dibawah ini.";
            $request['titletext'] = "6. Pilih Jenis Kunjungan";
            $request['buttontext'] = 'PILIH JENIS KUNJUNGAN';
            $request['rowtitle'] = "RUJUKAN FASKES 1_" . $nomorkartu . "#" . $jadwal . "#" . $tanggalperiksa . "," . "KONTROL_" . $nomorkartu . "#" . $jadwal . "#" . $tanggalperiksa . "," . "RUJUKAN ANTAR RS_" . $nomorkartu . "#" . $jadwal . "#" . $tanggalperiksa . ",";
            return $this->send_list($request);
        }
    }
    public function rujukan_peserta($pesan, Request $request)
    {

        try {
            $format = explode('_', $pesan)[1];
            $nomorkartu = explode('#', $format)[0];
            $jadwal = explode('#', $format)[1];
            $tanggalperiksa = explode('#', $format)[2];
        } catch (\Throwable $th) {
            //throw $th;
            $request['notif'] = "7 peserta " . $nomorkartu . " rujukan fktp error : " . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*7. Pilih Rujukan Faskes Tingkat 1*\nMohon maaf " . $th->getMessage();
            return $this->send_message($request);
        }

        $vclaim = new VclaimBPJSController();
        $request['nomorkartu'] = $nomorkartu;
        $rujukans = $vclaim->rujukan_peserta($request);
        if ($rujukans->metaData->code != 200) {
            $request['notif'] = "7 peserta " . $nomorkartu . " rujukan fktp error : " . $rujukans->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*7. Pilih Rujukan Faskes Tingkat 1*\nMohon maaf " . $rujukans->metaData->message;
            return $this->send_message($request);
        } else {
            $rowrujukan = null;
            $descrujukan = null;
            $rujukans = $rujukans->response->rujukan;

            foreach ($rujukans as $value) {
                if (Carbon::parse($value->tglKunjungan)->addMonth(3) > Carbon::now()) {
                    $rowrujukan =  $rowrujukan . "POLI " . $value->poliRujukan->nama  . " NO. " . $value->noKunjungan  . ',';
                    $descrujukan =  $descrujukan . '_RUJUKANFKTP#' . $value->noKunjungan . "#" . $jadwal . "#" . $tanggalperiksa . "#" . $nomorkartu . ',';
                }
            }
            if ($rowrujukan == null) {
                $request['notif'] = "7 peserta " . $nomorkartu . " rujukan fktp error : semua rujukan sudah 3 bulan lalu.";
                $this->send_notif($request);
                $request['message'] = "*7. Pilih Rujukan Faskes Tingkat 1*\nMohon maaf semua rujukan anda sudah lebih adri 3 bulan lalu. Silahkan untuk mendapatkan surat rujukan ke faskes 1.";
                return $this->send_message($request);
            }

            $request['contenttext'] = "Silahkan pilih nomor rujukan yang akan digunakan untuk mendaftar.";
            $request['titletext'] = "7. Pilih Rujukan Faskes Tingkat 1";
            $request['buttontext'] = 'PILIH RUJUKAN';
            $request['rowtitle'] = $rowrujukan;
            $request['rowdescription'] = $descrujukan;
            return $this->send_list($request);
        }
    }
    public function cek_rujukan($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorrujukan = explode('#', $format)[1];
            $jadwalid = explode('#', $format)[2];
            $tanggalperiksa = explode('#', $format)[3];
            $nomorkartu = explode('#', $format)[4];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorrujukan;
            $request['jenisrujukan'] = 1;
        } catch (\Throwable $th) {
            $request['notif'] = "8 cek " . $nomorkartu . " rujukan fktp error : " . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*8. Konfirmasi Rujukan FKTP*\n" . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $jumlah_sep =  $vclaim->rujukan_jumlah_sep($request);
        // gagal jumlah sep rujukan
        if ($jumlah_sep->metaData->code != 200) {
            $request['notif'] = "8 cek  " . $nomorkartu . " rujukan fktp error jumlah sep : "  . $jumlah_sep->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*8. Konfirmasi Rujukan FKTP*\n" . $jumlah_sep->metaData->message;
            return $this->send_message($request);
        }
        // berhasil cek jumlah sep rujukan
        else {
            // daftar pake rujukan
            if ($jumlah_sep->response->jumlahSEP == 0) {
                $rujukan  = $vclaim->rujukan_nomor($request);
                // gagal rujukan
                if ($rujukan->metaData->code != 200) {
                    $request['notif'] = "8 cek " . $nomorkartu . " rujukan fktp error rujukan : "  . $rujukan->metaData->message;
                    $this->send_notif($request);
                    $request['message'] = "*8. Konfirmasi Rujukan FKTP*\n" . $rujukan->metaData->message;
                    return $this->send_message($request);
                }
                // rujukan berhasil
                else {
                    // pasien lama
                    if (isset($rujukan->response->rujukan->peserta->mr->noMR)) {
                        try {
                            $request['nomorkartu'] = $rujukan->response->rujukan->peserta->noKartu;
                            $request['nama'] = $rujukan->response->rujukan->peserta->nama;
                            $request['nik'] = $rujukan->response->rujukan->peserta->nik;
                            $request['norm'] = $rujukan->response->rujukan->peserta->mr->noMR;
                            $request['status'] = $rujukan->response->rujukan->peserta->statusPeserta->keterangan;
                            $request['diagnosa'] = $rujukan->response->rujukan->diagnosa->nama;
                            $request['polirujukan'] = $rujukan->response->rujukan->poliRujukan->nama;
                            //    jika jadwal dan poli tujuan berbeda
                            // if (str_contains($request->polirujukan, $jadwaldokter->namasubspesialis)) {
                            //     $request['message'] = "*Pesan Gagal (203)*\nJadwal Poli (" . strtoupper($jadwaldokter->namasubspesialis) . ") dan Poli Tujuan Rujukan (" . strtoupper($request->polirujukan) . ") yang dipilih berbeda. \nSilahkan plih jadwal sesuai dengan rujukan anda.";
                            //     $this->send_message($request);
                            //     return $this->pilih_poli($pesan, $request);
                            // }
                            $request['nohp'] = $request->number;
                            $request['tanggalperiksa'] = $tanggalperiksa;
                            $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                            $request['kodedokter'] = $jadwaldokter->kodedokter;
                            $request['jampraktek'] = $jadwaldokter->jadwal;
                            $request['jeniskunjungan'] = 1;
                            $request['titletext'] = "8. Konfirmasi Rujukan FKTP";
                            $request['contenttext'] = "Jadwal dokter poliklinik yang dipilih sebagai berikut :\n*Poliklinik* : " . strtoupper($jadwaldokter->namasubspesialis) . "\n*Dokter* :  " . $jadwaldokter->namadokter . "\n*Jam Praktek* : " . $jadwaldokter->jadwal . "\n*Tanggal Periksa* :  " . $tanggalperiksa . "\n\nData pasien yang akan didaftarkan sebagai berikut :\n*Nama Pasien* : " . $request->nama . "\n*Status* : *" . $request->status . "*\n*NIK* : " . $request->nik . "\n*No BPJS* : " . $request->nomorkartu . "\n*No RM* : " . $request->norm . "\n\nData rujukan yang dipilih sebagai berikut : \n*No Rujukan* : " . $request->nomorreferensi . "\n*Poli Rujukan* : " . $request->polirujukan . "\n*Diagnosa* : " . $request->diagnosa .  "\n\nSebagai konfirmasi bahwa data yang diatas adalah benar pasien yang akan didaftarkan. Silahakan pilih tombol dibawah ini.";
                            $request['buttontext'] =  "DAFTAR RUJUKAN FKTP_" . $request->nomorreferensi . "#" . $jadwalid . "#" . $request->tanggalperiksa . ',BATAL PENDAFTARAN';
                            return $this->send_button($request);
                        } catch (\Throwable $th) {
                            $request['notif'] = "8 cek " . $nomorkartu . " rujukan fktp error trycatch : "  . $th->getMessage();
                            $this->send_notif($request);
                            $request['message'] = "*8. Konfirmasi Rujukan FKTP*\n"  . $th->getMessage();
                            return $this->send_message($request);
                        }
                    }
                    // pasien baru
                    else {
                        $request['notif'] = "8 cek " . $nomorkartu . " rujukan fktp error pasien baru";
                        $this->send_notif($request);
                        $request['message'] = "*8. Konfirmasi Rujukan FKTP*\nMohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                        return $this->send_message($request);
                    }
                }
            }
            // daftar pake surat kontrol
            else {
                $request['contenttext'] = "Mohon maaf kunjungan rujukan lebih dari satu. Anda harus mendaftar menggunakan *SURAT KONTROL* yang dibuat saat berobat sebelumnya.\nSilahkan daftar melalui *JENIS KUNJUNGAN* lainnya karena nomor rujukan FKTP telah digunakan.";
                $request['titletext'] = "8. Konfirmasi Rujukan FKTP";
                $request['buttontext'] = 'PILIH JENIS KUNJUNGAN';
                $request['rowtitle'] = "RUJUKAN FASKES 1_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . "," . "KONTROL_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . "," . "RUJUKAN ANTAR RS_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . ",";
                return $this->send_list($request);
            }
        }
    }
    public function daftar_rujukan_fktp($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorrujukan = explode('#', $format)[0];
            $jadwalid = explode('#', $format)[1];
            $tanggalperiksa = explode('#', $format)[2];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorrujukan;
            $request['jenisrujukan'] = 1;
        } catch (\Throwable $th) {
            $request['notif'] = '9 daftar rujukan fktp error :' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*Mohon Maaf (205)*\n" . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $jumlah_sep =  $vclaim->rujukan_jumlah_sep($request);
        // berhasil
        if ($jumlah_sep->metaData->code == 200) {
            // daftar pake rujukan
            if ($jumlah_sep->response->jumlahSEP == 0) {
                $rujukan  = $vclaim->rujukan_nomor($request);
                // rujukan 200 code
                if ($rujukan->metaData->code == 200) {
                    // pasien lama
                    if (isset($rujukan->response->rujukan->peserta->mr->noMR)) {
                        try {
                            $request['nomorkartu'] = $rujukan->response->rujukan->peserta->noKartu;
                            $request['nama'] = $rujukan->response->rujukan->peserta->nama;
                            $request['nik'] = $rujukan->response->rujukan->peserta->nik;
                            $request['norm'] = $rujukan->response->rujukan->peserta->mr->noMR;
                            $request['status'] = $rujukan->response->rujukan->peserta->statusPeserta->keterangan;
                            $request['diagnosa'] = $rujukan->response->rujukan->diagnosa->nama;
                            $request['polirujukan'] = $rujukan->response->rujukan->poliRujukan->nama;
                            $request['nohp'] = $request->number;
                            $request['tanggalperiksa'] = $tanggalperiksa;
                            $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                            $request['kodedokter'] = $jadwaldokter->kodedokter;
                            $request['jampraktek'] = $jadwaldokter->jadwal;
                            $request['jeniskunjungan'] = 1;
                            $antrian = new AntrianBPJSController();
                            $response = json_decode(json_encode($antrian->ambil_antrian($request)));
                            if ($response->metadata->code != 200) {
                                $request['message'] = "Maaf anda tidak bisa daftar : " .  $response->metadata->message . ". Silahkan daftar melalui offline.";
                                return $this->send_message($request);
                            } else {
                                return $response;
                            }
                        } catch (\Throwable $th) {
                            $request['message'] = "Error : " . $th;
                            return $this->send_message($request);
                        }
                    }
                    // pasien baru
                    else {
                        $request['message'] = "Error : Mohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                        return $this->send_message($request);
                    }
                }
                // rujukan error
                else {
                    $request['notif'] = '9 daftar rujukan fktp error : ' . $rujukan->metaData->message;;
                    $this->send_notif($request);
                    $request['message'] = "*9. Daftar Rujukan FKTP*\nMohon maaf " . $rujukan->metaData->message;
                    return $this->send_message($request);
                }
            }
            // daftar pake surat kontrol
            else {
                $request['notif'] = '9 daftar rujukan fktp error jumlah kunjungan lebih dari 1';
                $this->send_notif($request);
                $request['message'] = "Error : Mohon maaf kunjungan rujukan lebih dari 1. Anda harus mendaftar menggunakan Surat Kontrol. Silahkan hubungi admin. Terima kasih";
                return $this->send_message($request);
            }
        }
        // gagal rujukan
        else {
            $request['notif'] = '9 daftar rujukan fktp error jumlah sep :' . $jumlah_sep->metaData->message;
            $this->send_notif($request);
            $request['message'] = "Error : " . $jumlah_sep->metaData->message;
            return $this->send_message($request);
        }
    }
    public function surat_kontrol_peserta($pesan, Request $request)
    {
        try {
            $format = explode('_', $pesan)[1];
            $nomorkartu = explode('#', $format)[0];
            $jadwal = explode('#', $format)[1];
            $tanggal = Carbon::parse(explode('#', $format)[2]);
            $vclaim = new VclaimBPJSController();
            $request['nomorkartu'] = $nomorkartu;
            $request['tanggalperiksa'] = $tanggal->format('Y-m-d');
            $request['formatfilter'] = 2;
        } catch (\Throwable $th) {
            $request['notif'] = '7 peserta surat kontrol error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*7. Pilih Surat Kontrol*\nMohon maaf silahkan periksa format anda." . $th->getMessage();
            return $this->send_message($request);
        }
        $suratkontrol = $vclaim->surat_kontrol_peserta($request);
        $code = $suratkontrol->metaData->code;
        if ($code != 200) {
            $request['message'] = "*7. Pilih Surat Kontrol*\nMohon maaf " . $suratkontrol->metaData->message;
            return $this->send_message($request);
        } else {
            $rowsuratkontrol = null;
            $descsurarujukan = null;
            $suratkontrol = $suratkontrol->response->list;
            foreach ($suratkontrol as $value) {
                if ($value->terbitSEP == "Belum") {
                    if ($value->jnsKontrol == 2) {
                        $rowsuratkontrol =  $rowsuratkontrol .  $value->jnsPelayanan  . " " . $value->namaPoliTujuan  . " " . $value->namaDokter . ',';
                        $descsurarujukan =  $descsurarujukan . '_SURATKONTROL#' . $value->noSuratKontrol . "#" . $jadwal . "#" . $request->tanggalperiksa . ',';
                    }
                }
            }
            if ($rowsuratkontrol == null) {
                $request['notif'] = "7 peserta " . $nomorkartu . " surat kontrol error : semua surat kontrol telah digunakan";
                $this->send_notif($request);
                $request['message'] = "*7. Pilih Surat Kontrol*\nMohon maaf semua surat kontrol anda telah digunakan. \nUntuk penyesuaian yang akan datang silahkan minta daftarkan surat kontrol yang terintegrasi dengan sistem setelah pelayanan di Poliklinik. \nTerima kasih. ";
                return $this->send_message($request);
            };
            $request['contenttext'] = "Silahkan pilih nomor surat kontrol yang akan digunakan untuk mendaftar.";
            $request['titletext'] = "7. Pilih Surat Kontrol";
            $request['buttontext'] = 'PILIH SURAT KONTROL';
            $request['rowtitle'] = $rowsuratkontrol;
            $request['rowdescription'] = $descsurarujukan;
            return $this->send_list($request);
        }
    }
    public function cek_surat_kontrol($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorsuratkontrol = explode('#', $format)[1];
            $jadwalid = explode('#', $format)[2];
            $tanggalperiksa = explode('#', $format)[3];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorsuratkontrol;
        } catch (\Throwable $th) {
            $request['notif'] = '8 cek surat kontrol error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*8. Konfirmasi Surat Kontrol*\n" . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $suratkontrol =  $vclaim->surat_kontrol_nomor($request);
        // gagal jumlah sep rujukan
        if ($suratkontrol->metaData->code != 200) {
            $request['notif'] = '8 cek surat kontrol error : ' . $suratkontrol->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*8. Konfirmasi Surat Kontrol*\n" . $suratkontrol->metaData->message;
            return $this->send_message($request);
        }
        // berhasil cek jumlah sep rujukan
        else {
            $suratkontrol =  $suratkontrol->response;
            $tglkontrol = Carbon::createFromFormat('Y-m-d', $suratkontrol->tglRencanaKontrol, 'Asia/Jakarta');
            $tanggalperiksa = Carbon::createFromFormat('Y-m-d', $tanggalperiksa, 'Asia/Jakarta');
            // tanggal periksa kurang dari tanggal surat kontrol
            if ($tglkontrol->format('Y-m-d') != $tanggalperiksa->format('Y-m-d')) {
                $request['notif'] = "8 cek surat kontrol error : tanggal kunjungan (" . $tanggalperiksa->format('Y-m-d') . ") tidak sesuai dengan tanggal surat kontrol (" . $tglkontrol->format('Y-m-d') . "). Nomor surat kontrol : " . $nomorsuratkontrol;
                $this->send_notif($request);
                $request['message'] = "*8. Konfirmasi Surat Kontrol* \nMohon maaf tanggal kunjungan (" . $tanggalperiksa->format('Y-m-d') . ") tidak sesuai dengan tanggal surat kontrol (" . $tglkontrol->format('Y-m-d') . "). Silahkan lakukan pengajuan ubah tanggal surat kontrol.";
                return $this->send_message($request);
            }
            // jika berhasil
            else {
                $vclaim = new VclaimBPJSController();
                // $request['nomorreferensi'] = $suratkontrol->sep->provPerujuk->noRujukan;
                // $request['asalRujukan'] = $suratkontrol->sep->provPerujuk->asalRujukan;
                // if ($request->asalRujukan == 2) {
                //     $rujukan  = $vclaim->rujukan_rs_nomor($request);
                //     // dd($suratkontrol, $request->nomorreferensi,  $rujukan);
                // } else {
                //     $rujukan  = $vclaim->rujukan_nomor($request);
                // }
                $request['nomorkartu'] = $suratkontrol->sep->peserta->noKartu;
                $peserta = $vclaim->peserta_nomorkartu($request);
                $request['nomorreferensi'] = $nomorsuratkontrol;
                $peserta = $peserta->response->peserta;
                $request['nomorkartu'] = $peserta->noKartu;
                $request['nik'] = $peserta->nik;
                $request['nohp'] = $request->number;
                $request['nama'] = $peserta->nama;
                $request['norm'] = $peserta->mr->noMR;
                $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                $request['tanggalperiksa'] = $tanggalperiksa->format('Y-m-d');
                $request['kodedokter'] = $suratkontrol->kodeDokter;
                $request['namadokter'] = $suratkontrol->namaDokter;
                $request['jampraktek'] = $jadwaldokter->jadwal;
                $request['jeniskunjungan'] = 3;
                $request['status'] = $peserta->statusPeserta->keterangan;
                $request['diagnosa'] = $suratkontrol->sep->diagnosa;
                $request['polirujukan'] = $suratkontrol->namaPoliTujuan;
                // jika jadwal dan poli tujuan berbeda
                if ($request->kodedokter !=  $jadwaldokter->kodedokter) {
                    $request['message'] = "*8. Konfirmasi Surat Kontrol*\nMohon maaf Jadwal Dokter yang ada pilih (" . strtoupper($jadwaldokter->namadokter) . ") berbeda dengan Dokter Tujuan Surat Kontrol (" . strtoupper($request->namadokter) . ") anda. \nSilahkan plih jadwal sesuai dengan surat kontrol anda.";
                    $this->send_message($request);
                    return $this->pilih_poli($pesan, $request);
                }
                $request['titletext'] = "8. Konfirmasi Surat Kontrol";
                $request['contenttext'] = "Jadwal dokter poliklinik yang dipilih sebagai berikut :\n*Poliklinik* : " . strtoupper($jadwaldokter->namasubspesialis) . "\n*Dokter* :  " . $jadwaldokter->namadokter . "\n*Jam Praktek* : " . $jadwaldokter->jadwal . "\n*Tanggal Periksa* :  " . $tanggalperiksa . "\n\nData pasien yang akan didaftarkan sebagai berikut :\n*Nama Pasien* : " . $request->nama . "\n*Status* : *" . $request->status . "*\n*NIK* : " . $request->nik . "\n*No BPJS* : " . $request->nomorkartu . "\n*No RM* : " . $request->norm . "\n\nData surat kontrol yang dipilih sebagai berikut : \n*No Surat Kontrol* : " . $nomorsuratkontrol . "\n*No Rujukan* : " . $request->nomorreferensi . "\n*Poli Rujukan* : " . $request->polirujukan . "\n*Diagnosa* : " . $request->diagnosa .  "\n\nSebagai konfirmasi bahwa data yang diatas adalah benar pasien yang akan didaftarkan. Silahakan pilih tombol dibawah ini.";
                $request['buttontext'] =  "DAFTAR KONTROL_" . $nomorsuratkontrol . "#" . $jadwalid . "#" . $request->tanggalperiksa . ',BATAL PENDAFTARAN';
                return $this->send_button($request);
            }
        }
    }
    public function daftar_surat_kontrol($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorsuratkontrol = explode('#', $format)[0];
            $jadwalid = explode('#', $format)[1];
            $tanggalperiksa = explode('#', $format)[2];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorsuratkontrol;
        } catch (\Throwable $th) {
            //throw $th;
            $request['notif'] = "9 daftar " . $nomorsuratkontrol . " surat kontrol : " . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "Error : " . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $suratkontrol =  $vclaim->surat_kontrol_nomor($request);
        // // gagal jumlah sep rujukan
        if ($suratkontrol->metaData->code != 200) {
            $request['notif'] = "9 daftar " . $nomorsuratkontrol . " surat kontrol : " . $suratkontrol->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*Mohon maaf tidak dapat diproses (207)* \n" . $suratkontrol->metaData->message;
            return $this->send_message($request);
        }
        // // berhasil cek jumlah sep rujukan
        else {
            $suratkontrol =  $suratkontrol->response;
            $tglkontrol = Carbon::createFromFormat('Y-m-d', $suratkontrol->tglRencanaKontrol, 'Asia/Jakarta');
            $tanggalperiksa = Carbon::createFromFormat('Y-m-d', $tanggalperiksa, 'Asia/Jakarta');
            // tanggal periksa kurang dari tanggal surat kontrol
            if ($tglkontrol->format('Y-m-d') != $tanggalperiksa->format('Y-m-d')) {
                $request['message'] = "*Mohon Maaf Surat Kontrol (228)* \nTanggal kunjungan (" . $tanggalperiksa->format('Y-m-d') . ") tidak sesuai dengan tanggal surat kontrol (" . $tglkontrol->format('Y-m-d') . ").\nSilahkan daftar dihari sesuai surat kontrol.";
                return $this->send_message($request);
            }
            // // jika berhasil
            else {
                $vclaim = new VclaimBPJSController();
                // $request['nomorreferensi'] = $suratkontrol->sep->provPerujuk->noRujukan;
                // $request['asalRujukan'] = $suratkontrol->sep->provPerujuk->asalRujukan;
                // if ($request->asalRujukan == 2) {
                //     $rujukan  = $vclaim->rujukan_rs_nomor($request);
                // } else {
                //     $rujukan  = $vclaim->rujukan_nomor($request);
                // }
                $request['nomorkartu'] = $suratkontrol->sep->peserta->noKartu;
                $peserta = $vclaim->peserta_nomorkartu($request);
                $request['nomorreferensi'] = $nomorsuratkontrol;
                $peserta = $peserta->response->peserta;
                $request['nomorkartu'] = $peserta->noKartu;
                $request['nik'] = $peserta->nik;
                $request['nohp'] = $request->number;
                $request['nama'] = $peserta->nama;
                $request['norm'] = $peserta->mr->noMR;
                $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                $request['tanggalperiksa'] = $tanggalperiksa->format('Y-m-d');
                $request['kodedokter'] = $suratkontrol->kodeDokter;
                $request['namadokter'] = $suratkontrol->namaDokter;
                $request['jampraktek'] = $jadwaldokter->jadwal;
                $request['jeniskunjungan'] = 3;
                $request['status'] = $peserta->statusPeserta->keterangan;
                $request['diagnosa'] = $suratkontrol->sep->diagnosa;
                $request['polirujukan'] = $suratkontrol->namaPoliTujuan;
                // jika jadwal dan poli tujuan berbeda
                if ($request->kodedokter !=  $jadwaldokter->kodedokter) {
                    $request['message'] = "*8. Konfirmasi Surat Kontrol*\nMohon maaf Jadwal Dokter yang ada pilih (" . strtoupper($jadwaldokter->namadokter) . ") berbeda dengan Dokter Tujuan Surat Kontrol (" . strtoupper($request->namadokter) . ") anda. \nSilahkan plih jadwal sesuai dengan rujukan anda.";
                    $this->send_message($request);
                    return $this->pilih_poli($pesan, $request);
                }
                $antrian = new AntrianBPJSController();
                $response = json_decode(json_encode($antrian->ambil_antrian($request)));
                if ($response->metadata->code != 200) {
                    $request['message'] = "Maaf anda tidak bisa daftar : " .  $response->metadata->message . ". Silahkan daftar melalui offline.";
                    return $this->send_message($request);
                } else {
                    return $response;
                }
            }
        }
    }
    public function rujukan_rs_peserta($pesan, Request $request)
    {
        $format = explode('_', $pesan)[1];
        $nomorkartu = explode('#', $format)[0];
        $jadwal = explode('#', $format)[1];
        $tanggalperiksa = explode('#', $format)[2];
        $vclaim = new VclaimBPJSController();
        $request['nomorkartu'] = $nomorkartu;
        $rujukans = $vclaim->rujukan_rs_peserta($request);
        if ($rujukans->metaData->code != 200) {
            $request['message'] = "*7. Rujukan Antar RS*\n Mohon maaf" . $rujukans->metaData->message;
            return $this->send_message($request);
        } else {
            $rowrujukan = null;
            $descrujukan = null;
            $rujukans = $rujukans->response->rujukan;
            foreach ($rujukans as $value) {
                if (Carbon::parse($value->tglKunjungan)->addMonth(3) > Carbon::now()) {
                    $rowrujukan =  $rowrujukan . "POLI " . $value->poliRujukan->nama  . " NO. " . $value->noKunjungan  . ',';
                    $descrujukan =  $descrujukan . '_RUJUKANRS#' . $value->noKunjungan . "#" . $jadwal . "#" . $tanggalperiksa . "#" . $nomorkartu . ',';
                }
            }
            $request['contenttext'] = "Silahkan pilih nomor rujukan antar RS yang akan digunakan untuk mendaftar.";
            $request['titletext'] = "7. Rujukan Antar RS";
            $request['buttontext'] = 'PILIH RUJUKAN RS';
            $request['rowtitle'] = $rowrujukan;
            $request['rowdescription'] = $descrujukan;
            return $this->send_list($request);
        }
    }
    public function cek_rujukan_rs($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorrujukan = explode('#', $format)[1];
            $jadwalid = explode('#', $format)[2];
            $tanggalperiksa = explode('#', $format)[3];
            $nomorkartu = explode('#', $format)[4];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorrujukan;
            $request['jenisrujukan'] = 2;
        } catch (\Throwable $th) {
            //throw $th;
            $request['notif'] = '8 cek rujukan rs error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "Error : " . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $jumlah_sep =  $vclaim->rujukan_jumlah_sep($request);
        // gagal jumlah sep rujukan
        if ($jumlah_sep->metaData->code != 200) {
            $request['notif'] = '8 cek rujukan rs error : ' . $jumlah_sep->metaData->message;
            $this->send_notif($request);
            $request['message'] = "*8. Konfirmasi Rujukan Antar*\n" . $jumlah_sep->metaData->message;
            return $this->send_message($request);
        }
        // berhasil cek jumlah sep rujukan
        else {
            // daftar pake rujukan
            if ($jumlah_sep->response->jumlahSEP == 0) {
                $rujukan  = $vclaim->rujukan_rs_nomor($request);
                // gagal rujukan
                if ($rujukan->metaData->code != 200) {
                    $request['notif'] = '8 cek rujukan rs error : ' . $jumlah_sep->metaData->message;
                    $this->send_notif($request);
                    $request['message'] = "*8. Konfirmasi Rujukan Antar*\n" . $rujukan->metaData->message;
                    return $this->send_message($request);
                }
                // rujukan berhasil
                else {
                    // pasien lama
                    if (isset($rujukan->response->rujukan->peserta->mr->noMR)) {
                        try {
                            $request['nomorkartu'] = $rujukan->response->rujukan->peserta->noKartu;
                            $request['nama'] = $rujukan->response->rujukan->peserta->nama;
                            $request['nik'] = $rujukan->response->rujukan->peserta->nik;
                            $request['norm'] = $rujukan->response->rujukan->peserta->mr->noMR;
                            $request['status'] = $rujukan->response->rujukan->peserta->statusPeserta->keterangan;
                            $request['diagnosa'] = $rujukan->response->rujukan->diagnosa->nama;
                            $request['polirujukan'] = $rujukan->response->rujukan->poliRujukan->nama;
                            //    jika jadwal dan poli tujuan berbeda
                            // if (str_contains($request->polirujukan, $jadwaldokter->namasubspesialis)) {
                            //     $request['message'] = "*Mohon Maaf (203)*\nJadwal Poli (" . strtoupper($jadwaldokter->namasubspesialis) . ") dan Poli Tujuan Rujukan (" . strtoupper($request->polirujukan) . ") yang dipilih berbeda. \nSilahkan plih jadwal sesuai dengan rujukan anda.";
                            //     $this->send_message($request);
                            //     return $this->pilih_poli($pesan, $request);
                            // }
                            $request['nohp'] = $request->number;
                            $request['tanggalperiksa'] = $tanggalperiksa;
                            $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                            $request['kodedokter'] = $jadwaldokter->kodedokter;
                            $request['jampraktek'] = $jadwaldokter->jadwal;
                            $request['jeniskunjungan'] = 4;
                            $request['titletext'] = "8. Konfirmasi Rujukan Antar RS";
                            $request['contenttext'] = "Jadwal dokter poliklinik yang dipilih sebagai berikut :\n*Poliklinik* : " . strtoupper($jadwaldokter->namasubspesialis) . "\n*Dokter* :  " . $jadwaldokter->namadokter . "\n*Jam Praktek* : " . $jadwaldokter->jadwal . "\n*Tanggal Periksa* :  " . $tanggalperiksa . "\n\nData pasien yang akan didaftarkan sebagai berikut :\n*Nama Pasien* : " . $request->nama . "\n*Status* : *" . $request->status . "*\n*NIK* : " . $request->nik . "\n*No BPJS* : " . $request->nomorkartu . "\n*No RM* : " . $request->norm . "\n\nData rujukan yang dipilih sebagai berikut : \n*No Rujukan* : " . $request->nomorreferensi . "\n*Poli Rujukan* : " . $request->polirujukan . "\n*Diagnosa* : " . $request->diagnosa .  "\n\nSebagai konfirmasi bahwa data yang diatas adalah benar pasien yang akan didaftarkan. Silahakan pilih tombol dibawah ini.";
                            $request['buttontext'] =  "DAFTAR RUJUKAN RS_" . $request->nomorreferensi . "#" . $jadwalid . "#" . $request->tanggalperiksa . ',BATAL PENDAFTARAN';
                            return $this->send_button($request);
                        } catch (\Throwable $th) {
                            $request['notif'] = '8 cek rujukan rs error : ' . $th->getMessage();
                            $this->send_notif($request);
                            $request['message'] = "*8. Konfirmasi Rujukan Antar*\n" . $th->getMessage();
                            return $this->send_message($request);
                        }
                    }
                    // pasien baru
                    else {
                        $request['message'] = "Pesan 102 : Mohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                        return $this->send_message($request);
                    }
                }
            }
            // daftar pake surat kontrol
            else {
                $request['contenttext'] = "*Mohon Maaf Tidak Bisa Daftar Rujukan (202)*\nKunjungan rujukan lebih dari satu. Anda harus mendaftar menggunakan *SURAT KONTROL* yang dibuat saat berobat sebelumnya.\nSilahkan daftar melalui *JENIS KUNJUNGAN* lainnya karena nomor rujukan FKTP telah digunakan.";
                $request['titletext'] = "Pilih Jenis Kunjungan";
                $request['buttontext'] = 'PILIH JENIS KUNJUNGAN';
                $request['rowtitle'] = "RUJUKAN FASKES 1_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . ","  . "KONTROL_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . "," . "RUJUKAN ANTAR RS_" . $nomorkartu . "#" . $jadwalid . "#" . $tanggalperiksa . ",";
                return $this->send_list($request);
            }
        }
    }
    public function daftar_rujukan_rs($pesan, Request $request)
    {
        // init
        try {
            $format = explode('_', $pesan)[1];
            $nomorrujukan = explode('#', $format)[0];
            $jadwalid = explode('#', $format)[1];
            $tanggalperiksa = explode('#', $format)[2];
            $jadwaldokter = JadwalDokter::find($jadwalid);
            $request['nomorreferensi'] = $nomorrujukan;
            $request['jenisrujukan'] = 2;
        } catch (\Throwable $th) {
            $request['notif'] = '9 cek rujukan rs error : ' . $th->getMessage();
            $this->send_notif($request);
            $request['message'] = "*Mohon Maaf (205)*\n" . $th->getMessage() . "\nSilahkan hubungi admin. Terima kasih.";
            return $this->send_message($request);
        }
        $vclaim = new VclaimBPJSController();
        $jumlah_sep =  $vclaim->rujukan_jumlah_sep($request);
        //    server bpjs gangguan
        if ($jumlah_sep ==  null) {
            $request['message'] = "Mohon maaf server bpjs sedang gangguan.";
            return $this->send_message($request);
        }
        // berhasil
        else if ($jumlah_sep->metaData->code == 200) {
            // daftar pake rujukan
            if ($jumlah_sep->response->jumlahSEP == 0) {
                $rujukan  = $vclaim->rujukan_rs_nomor($request);
                // rujukan 200 code
                if ($rujukan->metaData->code == 200) {
                    // pasien lama
                    if (isset($rujukan->response->rujukan->peserta->mr->noMR)) {
                        try {
                            $request['nomorkartu'] = $rujukan->response->rujukan->peserta->noKartu;
                            $request['nama'] = $rujukan->response->rujukan->peserta->nama;
                            $request['nik'] = $rujukan->response->rujukan->peserta->nik;
                            $request['norm'] = $rujukan->response->rujukan->peserta->mr->noMR;
                            $request['status'] = $rujukan->response->rujukan->peserta->statusPeserta->keterangan;
                            $request['diagnosa'] = $rujukan->response->rujukan->diagnosa->nama;
                            $request['polirujukan'] = $rujukan->response->rujukan->poliRujukan->nama;
                            $request['nohp'] = $request->number;
                            $request['tanggalperiksa'] = $tanggalperiksa;
                            $request['kodepoli'] = $jadwaldokter->kodesubspesialis;
                            $request['kodedokter'] = $jadwaldokter->kodedokter;
                            $request['jampraktek'] = $jadwaldokter->jadwal;
                            $request['jeniskunjungan'] = 4;
                            $request['jenisrujukan'] = 2;
                            $antrian = new AntrianBPJSController();
                            $response = json_decode(json_encode($antrian->ambil_antrian($request)));
                            if ($response->metadata->code != 200) {
                                $request['message'] = "Maaf anda tidak bisa daftar : " .  $response->metadata->message . ". Silahkan daftar melalui offline.";
                                return $this->send_message($request);
                            } else {
                                return $response;
                            }
                        } catch (\Throwable $th) {
                            $request['message'] = "Error : " . $th;
                            return $this->send_message($request);
                        }
                    }
                    // pasien baru
                    else {
                        $request['message'] = "Error : Mohon maaf untuk pasien baru tidak bisa daftar melalui whatsapp. Silahkan untuk daftar langsung ke RSUD Waled. Terima kasih.";
                        return $this->send_message($request);
                    }
                }
                // rujukan error
                else {
                    $request['message'] = "Error : " . $rujukan->metaData->message;
                    return $this->send_message($request);
                }
            }
            // daftar pake surat kontrol
            else {
                $request['message'] = "Error : Mohon maaf kunjungan rujukan lebih dari 1. Anda harus mendaftar menggunakan Surat Kontrol. Silahkan hubungi admin. Terima kasih";
                return $this->send_message($request);
            }
        }
        // gagal rujukan
        else {
            $request['message'] = "Error : " . $jumlah_sep->metaData->message;
            return $this->send_message($request);
        }
    }
}
