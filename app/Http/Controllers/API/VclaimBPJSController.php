<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\SuratKontrol;
use Carbon\Carbon;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

class VclaimBPJSController extends Controller
{
    // public $baseUrl = 'https://apijkn-dev.bpjs-kesehatan.go.id/vclaim-rest-dev/';
    public $baseUrl = 'https://apijkn.bpjs-kesehatan.go.id/vclaim-rest/';

    public static function signature()
    {
        $cons_id =  env('VCLAIM_CONS_ID');
        $secretKey = env('VCLAIM_SECRET_KEY');
        $userkey = env('VCLAIM_USER_KEY');

        date_default_timezone_set('UTC');
        $tStamp = strval(time() - strtotime('1970-01-01 00:00:00'));
        $signature = hash_hmac('sha256', $cons_id . "&" . $tStamp, $secretKey, true);
        $encodedSignature = base64_encode($signature);

        $response = array(
            'user_key' => $userkey,
            'x-cons-id' => $cons_id,
            'x-timestamp' => $tStamp,
            'x-signature' => $encodedSignature,
            'decrypt_key' => $cons_id . $secretKey . $tStamp,
        );
        return $response;
    }
    public static function stringDecrypt($key, $string)
    {
        $encrypt_method = 'AES-256-CBC';
        $key_hash = hex2bin(hash('sha256', $key));
        $iv = substr(hex2bin(hash('sha256', $key)), 0, 16);
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key_hash, OPENSSL_RAW_DATA, $iv);
        $output = \LZCompressor\LZString::decompressFromEncodedURIComponent($output);
        return $output;
    }
    public function ref_provinsi()
    {
        $url = $this->baseUrl . "referensi/propinsi";
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function ref_kabupaten(Request $request)
    {
        $url = $this->baseUrl . "referensi/kabupaten/propinsi/" . $request->provinsi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function ref_kecamatan(Request $request)
    {
        $url = $this->baseUrl . "referensi/kecamatan/kabupaten/" . $request->kabupaten;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    // api monitoring bpjs
    public function monitoring_pelayanan_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
            "tanggalperiksa" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        if ($request->tanggalperiksa == null) {
            $time = Carbon::now();
        } else {
            $time = Carbon::parse($request->tanggalperiksa);
        }
        $tanggal_akhir = $time->format('Y-m-d');
        $tanggal_lama = $time->subDays(89)->format('Y-m-d');
        $url = $this->baseUrl . "monitoring/HistoriPelayanan/NoKartu/" . $request->nomorkartu . "/tglMulai/" . $tanggal_lama . "/tglAkhir/" . $tanggal_akhir;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    // api peserta bpjs
    public function peserta_nomorkartu(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        if ($request->tanggalperiksa == null) {
            $request['tanggalperiksa'] = Carbon::now()->format('Y-m-d');
        }
        $url = $this->baseUrl . "Peserta/nokartu/" . $request->nomorkartu . "/tglSEP/" . $request->tanggalperiksa;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        if ($response->status() != 200) {
            return json_decode(json_encode([
                'metaData' => [
                    'code' => 500,
                    'message' => "Sistem tidak terhubung ke Bridging VClaim BPJS",
                ]
            ]));
        }
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function peserta_nik(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nik" => "required|digits:16",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        if ($request->tanggalperiksa == null) {
            $request['tanggalperiksa'] = Carbon::now()->format('Y-m-d');
        }
        $url = $this->baseUrl . "Peserta/nik/" . $request->nik . "/tglSEP/" . $request->tanggalperiksa;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    // Cari Rujukan
    public function rujukan_nomor(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "Rujukan/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function rujukan_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }

        $url = $this->baseUrl . "Rujukan/List/Peserta/" . $request->nomorkartu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function rujukan_rs_nomor(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }

        $url = $this->baseUrl . "Rujukan/RS/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function rujukan_rs_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }

        $url = $this->baseUrl . "Rujukan/RS/List/Peserta/" . $request->nomorkartu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function rujukan_jumlah_sep(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "jenisrujukan" => "required",
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "Rujukan/JumlahSEP/" . $request->jenisrujukan . "/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response == null) {
            return $response;
        } else if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        } else if ($response->metaData->code == 201) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    // Pembuatan Rencana Kontrol/SPRI
    public function insert_rencana_kontrol(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "kodepoli" => "required",
            "tanggalperiksa" => "required",
            "kodedokter" => "required",
            "nomorsep" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metaData' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        // insert surat kontrol
        $url = $this->baseUrl . "RencanaKontrol/insert";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "noSEP" => $request->nomorsep,
                    "kodeDokter" => $request->kodedokter,
                    "poliKontrol" => $request->kodepoli,
                    "tglRencanaKontrol" => $request->tanggalperiksa,
                    "user" => "Antrian RSUD Waled",
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
            // insert database surat kontrol
            $surat_kontrol = $response->response;
            // SuratKontrol::create([
            //     "noSuratKontrol" => $surat_kontrol->noSuratKontrol,
            //     "tglTerbitKontrol" => Carbon::now()->format("Y-m-d"),
            //     "tglRencanaKontrol" => $surat_kontrol->tglRencanaKontrol,
            //     "noRujukan" => $request->nomorreferensi,
            //     "namaDokter" => $surat_kontrol->namaDokter,
            //     "noKartu" => $surat_kontrol->noKartu,
            //     "nama" => $surat_kontrol->nama,
            //     "kelamin" => $surat_kontrol->kelamin,
            //     "tglLahir" => $surat_kontrol->tglLahir,
            //     "namaDiagnosa" => $surat_kontrol->namaDiagnosa,
            //     "poliTujuan" => $request->kodepoli,
            //     "kodeDokter" => $request->kodedokter,
            //     "user" => "System Ambil Antrian",
            //     "noSepAsalKontrol" => $request->nomorsep,
            // ]);
        }
        return $response;
    }
    public function surat_kontrol_insert(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "noSEP" => "required",
            "kodeDokter" => "required",
            "poliKontrol" => "required",
            "tglRencanaKontrol" => "required",
            "user" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metaData' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $url = $this->baseUrl . "RencanaKontrol/insert";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "noSEP" => $request->noSEP,
                    "kodeDokter" => $request->kodeDokter,
                    "poliKontrol" => $request->poliKontrol,
                    "tglRencanaKontrol" => $request->tglRencanaKontrol,
                    "user" => $request->user,
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
            // insert database surat kontrol
            $suratkontrol = $response->response;
            SuratKontrol::create([
                "tglTerbitKontrol" => Carbon::now()->format('Y-m-d'),
                "tglRencanaKontrol" => $suratkontrol->tglRencanaKontrol,
                "poliTujuan" => $request->poliKontrol,
                // "namaPoliTujuan" => $poli->namasubspesialis,
                "kodeDokter" => $request->kodeDokter,
                "namaDokter" => $suratkontrol->namaDokter,
                "noSuratKontrol" => $suratkontrol->noSuratKontrol,
                "namaJnsKontrol" => "Surat Kontrol",
                "noSepAsalKontrol" => $request->noSEP,
                "noKartu" => $suratkontrol->noKartu,
                "nama" => $suratkontrol->nama,
                "kelamin" => $suratkontrol->kelamin,
                "tglLahir" => $suratkontrol->tglLahir,
                "user" => $request->user,
            ]);
        }
        return $response;
    }
    public function surat_kontrol_update(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "noSuratKontrol" => "required",
            "noSEP" => "required",
            "kodeDokter" => "required",
            "poliKontrol" => "required",
            "tglRencanaKontrol" => "required",
            "user" => "required",
        ]);
        if ($validator->fails()) {
            return  json_decode(json_encode(['metaData' => ['code' => 201, 'message' => $validator->errors()->first(),],]));
        }
        $url = $this->baseUrl . "RencanaKontrol/Update";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('PUT', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "noSuratKontrol" => $request->noSuratKontrol,
                    "noSEP" => $request->noSEP,
                    "kodeDokter" => $request->kodeDokter,
                    "poliKontrol" => $request->poliKontrol,
                    "tglRencanaKontrol" => $request->tglRencanaKontrol,
                    "user" => $request->user,
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
            $suratkontrol = $response->response;
            $suratkontrols = SuratKontrol::where('noSuratKontrol', $suratkontrol->noSuratKontrol)->first();
            $suratkontrols->update([
                "poliKontrol" => $request->poliKontrol,
                "kodeDokter" => $request->kodeDokter,
                "noSuratKontrol" => $suratkontrol->noSuratKontrol,
                "tglRencanaKontrol" => $suratkontrol->tglRencanaKontrol,
                "namaDokter" => $suratkontrol->namaDokter,
                "noKartu" => $suratkontrol->noKartu,
                "nama" => $suratkontrol->nama,
                "tglLahir" => $suratkontrol->tglLahir,
                "kelamin" => $suratkontrol->kelamin,
            ]);
        }
        return $response;
    }
    public function surat_kontrol_delete(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "noSuratKontrol" => "required",
            "user" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metaData' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $url = $this->baseUrl . "RencanaKontrol/Delete";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request("DELETE", $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "t_suratkontrol" => [
                        "noSuratKontrol" => $request->noSuratKontrol,
                        "user" =>  $request->user,
                    ],
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function surat_kontrol_nomor(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "RencanaKontrol/noSuratKontrol/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function surat_kontrol_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "tanggalperiksa" => "required",
            "nomorkartu" => "required",
            "formatfilter" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $tanggalperiksa = Carbon::parse($request->tanggalperiksa);
        $bulan = $tanggalperiksa->month;
        $tahun = $tanggalperiksa->year;
        $url = $this->baseUrl . "RencanaKontrol/ListRencanaKontrol/Bulan/" . sprintf("%02d", $bulan)  . "/Tahun/" . $tahun . "/Nokartu/" . $request->nomorkartu . "/filter/" . $request->formatfilter;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function data_surat_kontrol(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "tanggal_awal" => "required",
            "tanggal_akhir" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "RencanaKontrol/ListRencanaKontrol/tglAwal/" . $request->tanggal_awal . "/tglAkhir/" . $request->tanggal_akhir . "/filter/2";
        // dd($url);
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function surat_kontrol_poli(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "jeniskontrol" => "required",
            "nomor" => "required",
            "tanggalkontrol" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "RencanaKontrol/ListSpesialistik/JnsKontrol/" . $request->jeniskontrol . "/nomor/" . $request->nomor . "/TglRencanaKontrol/" . $request->tanggalkontrol;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function surat_kontrol_dokter(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "jeniskontrol" => "required",
            "kodepoli" => "required",
            "tanggalkontrol" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "RencanaKontrol/JadwalPraktekDokter/JnsKontrol/" . $request->jeniskontrol . "/KdPoli/" . $request->kodepoli . "/TglRencanaKontrol/" . $request->tanggalkontrol;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    // Pembuatan SEP
    public function insert_sep(Request $request)
    {
        // if ($request->nomorsuratkontrol) {
        //     $request['tujuanKunj'] = "2";
        //     $request['flagProcedure'] = "";
        //     $request['kdPenunjang'] = "";
        //     $request['assesmentPel'] = "5";
        //     $request['noSurat'] = $request->nomorsuratkontrol;
        //     // $request['kodeDPJP'] = $request->kodedokter;
        //     // $request['dpjpLayan'] = $request->kodedokter;
        // } else {
        //     $request['tujuanKunj'] = "0";
        //     $request['flagProcedure'] = "";
        //     $request['kdPenunjang'] = "";
        //     $request['assesmentPel'] = "";
        //     $request['noSurat'] = "";
        //     $request['kodeDPJP'] = "";
        //     $request['dpjpLayan'] = $request->kodedokter;
        // }
        $url = $this->baseUrl . "SEP/2.0/insert";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "t_sep" => [
                        "noKartu" => $request->noKartu,
                        "tglSep" => $request->tglSep,
                        "ppkPelayanan" => $request->ppkPelayanan,
                        "jnsPelayanan" => $request->jnsPelayanan,
                        "klsRawat" => [
                            "klsRawatHak" => $request->klsRawatHak,
                            "klsRawatNaik" => $request->klsRawatNaik,
                            "pembiayaan" => $request->pembiayaan,
                            "penanggungJawab" => $request->penanggungJawab,
                        ],
                        "noMR" => $request->noMR,
                        "rujukan" => [
                            "asalRujukan" =>  $request->asalRujukan,
                            "tglRujukan" =>  $request->tglRujukan,
                            "noRujukan" =>  $request->noRujukan,
                            "ppkRujukan" =>  $request->ppkRujukan,
                        ],
                        "catatan" => $request->catatan,
                        "diagAwal" => $request->diagAwal,
                        "poli" => [
                            "tujuan" => $request->tujuan,
                            "eksekutif" => $request->eksekutif,
                        ],
                        "cob" => [
                            "cob" => "0"
                        ],
                        "katarak" => [
                            "katarak" => "0"
                        ],
                        "jaminan" => [
                            "lakaLantas" => "0",
                            "noLP" => "",
                            "penjamin" => [
                                "tglKejadian" => "",
                                "keterangan" => "",
                                "suplesi" => [
                                    "suplesi" => "0",
                                    "noSepSuplesi" => "",
                                    "lokasiLaka" => [
                                        "kdPropinsi" => "",
                                        "kdKabupaten" => "",
                                        "kdKecamatan" => ""
                                    ]
                                ]
                            ]
                        ],
                        "tujuanKunj" => $request->tujuanKunj,
                        "flagProcedure" => $request->flagProcedure,
                        "kdPenunjang" => $request->kdPenunjang,
                        "assesmentPel" => $request->assesmentPel,
                        "skdp" => [
                            "noSurat" => $request->noSurat,
                            "kodeDPJP" => $request->kodeDPJP,
                        ],
                        "dpjpLayan" => $request->dpjpLayan,
                        "noTelp" => $request->nohp,
                        "user" => "Admin RSUD Waled"
                    ]
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function sep_insert(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "noKartu" => "required",
            "tglSep" => "required",
            "ppkPelayanan" => "required",
            "jnsPelayanan" => "required",

            "klsRawatHak" => "required",

            "asalRujukan" => "required",
            "tglRujukan" => "required",
            "noRujukan" => "required",
            "ppkRujukan" => "required",

            "catatan" => "required",
            "diagAwal" => "required",

            "tujuan" => "required",
            "eksekutif" => "required",

            "tujuanKunj" => "required",
            // "flagProcedure" => "required",
            // "kdPenunjang" => "required",
            // "assesmentPel" => "required",

            // "noSurat" => "required",
            // "kodeDPJP" => "required",
            "dpjpLayan" => "required",
            "noTelp" => "required",
            "user" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metaData' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $url = $this->baseUrl . "SEP/2.0/insert";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "t_sep" => [
                        "noKartu" => $request->noKartu,
                        "tglSep" => $request->tglSep,
                        "ppkPelayanan" => $request->ppkPelayanan,
                        "jnsPelayanan" => $request->jnsPelayanan,
                        "klsRawat" => [
                            "klsRawatHak" => $request->klsRawatHak,
                            "klsRawatNaik" => $request->klsRawatNaik,
                            "pembiayaan" => $request->pembiayaan,
                            "penanggungJawab" => $request->penanggungJawab,
                        ],
                        "noMR" => $request->noMR,
                        "rujukan" => [
                            "asalRujukan" =>  $request->asalRujukan,
                            "tglRujukan" =>  $request->tglRujukan,
                            "noRujukan" =>  $request->noRujukan,
                            "ppkRujukan" =>  $request->ppkRujukan,
                        ],
                        "catatan" => $request->catatan,
                        "diagAwal" => $request->diagAwal,
                        "poli" => [
                            "tujuan" => $request->tujuan,
                            "eksekutif" => $request->eksekutif,
                        ],
                        "cob" => [
                            "cob" => "0"
                        ],
                        "katarak" => [
                            "katarak" => "0"
                        ],
                        "jaminan" => [
                            "lakaLantas" => "0",
                            "noLP" => "",
                            "penjamin" => [
                                "tglKejadian" => "",
                                "keterangan" => "",
                                "suplesi" => [
                                    "suplesi" => "0",
                                    "noSepSuplesi" => "",
                                    "lokasiLaka" => [
                                        "kdPropinsi" => "",
                                        "kdKabupaten" => "",
                                        "kdKecamatan" => ""
                                    ]
                                ]
                            ]
                        ],
                        "tujuanKunj" => $request->tujuanKunj,
                        "flagProcedure" => $request->flagProcedure,
                        "kdPenunjang" => $request->kdPenunjang,
                        "assesmentPel" => $request->assesmentPel,
                        "skdp" => [
                            "noSurat" => $request->noSurat,
                            "kodeDPJP" => $request->kodeDPJP,
                        ],
                        "dpjpLayan" => $request->dpjpLayan,
                        "noTelp" => $request->noTelp,
                        "user" =>  $request->user,
                    ]
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function delete_sep(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "noSep" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        // delete sep
        $url = $this->baseUrl . "SEP/2.0/delete";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('DELETE', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "t_sep" => [
                        "noSep" => $request->noSep,
                        "user" => "RSUD Waled",
                    ]
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function cari_sep(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "noSep" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "SEP/" . $request->noSep;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function sep_internal(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "noSep" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = $this->baseUrl . "SEP/Internal/" . $request->noSep;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function sep_internal_delete(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "noSep" => "required",
            "noSurat" => "required",
            "tglRujukanInternal" => "required",
            "kdPoliTuj" => "required",
        ]);
        if ($validator->fails()) {
            return json_decode(json_encode(['metadata' => ['code' => 201, 'message' => $validator->errors()->first(),],]));
        }
        // delete sep
        $url = $this->baseUrl . "SEP/Internal/delete";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('DELETE', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "request" => [
                    "t_sep" => [
                        "noSep" => $request->noSep,
                        "noSurat" => $request->noSurat,
                        "tglRujukanInternal" => $request->tglRujukanInternal,
                        "kdPoliTuj" => $request->kdPoliTuj,
                        "user" => "RSUD Waled",
                    ]
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metaData->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
}
