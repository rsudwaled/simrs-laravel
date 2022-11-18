<?php

namespace App\Http\Controllers\BPJS\Vclaim;

use App\Http\Controllers\BPJS\ApiBPJSController;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

class VclaimController extends ApiBPJSController
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
    public function response_decrypt($response, $signature)
    {
        if ($response->failed()) {
            return $this->sendError($response->reason(),  $response->json('response'), $response->status());
        } else {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->json('response'));
            $data = json_decode($decrypt);
            if ($response->json('metaData.code') == 1 || $response->json('metaData.code') == 0) {
                $code = 200;
            } else {
                $code = $response->json('metaData.code');
            }
            return $this->sendResponse($response->json('metaData.message'), $data, $code);
        }
    }
    public function response_no_decrypt($response)
    {
        if ($response->failed()) {
            return $this->sendError($response->reason(),  $response->json('response'), $response->status());
        } else {
            return $this->sendResponse($response->json('metaData.message'), $response->json('response'), $response->json('metaData.code'));
        }
    }
    // API VCLAIM
    // MONITORING
    public function monitoring_data_kunjungan(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "tanggal" => "required|date",
            "jenispelayanan" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = env('VCLAIM_URL') . "Monitoring/Kunjungan/Tanggal/" . $request->tanggal . "/JnsPelayanan/" . $request->jenispelayanan;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function monitoring_data_klaim(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "tanggalpulang" => "required|date",
            "jenispelayanan" => "required",
            "statusklaim" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = env('VCLAIM_URL') . "Monitoring/Klaim/Tanggal/" . $request->tanggalpulang . "/JnsPelayanan/" . $request->jenispelayanan . "/Status/" . $request->statusklaim;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function monitoring_pelayanan_peserta(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
            "tanggalmulai" => "required|date",
            "tanggalakhir" => "required|date",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = env('VCLAIM_URL') . "monitoring/HistoriPelayanan/NoKartu/" . $request->nomorkartu . "/tglMulai/" . $request->tanggalmulai . "/tglAkhir/" . $request->tanggalakhir;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function monitoring_klaim_jasaraharja(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "jenispelayanan" => "required",
            "tanggalmulai" => "required|date",
            "tanggalakhir" => "required|date",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = env('VCLAIM_URL') . "monitoring/JasaRaharja/JnsPelayanan/" . $request->jenispelayanan . "/tglMulai/" . $request->tanggalmulai . "/tglAkhir/" . $request->tanggalakhir;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    // PESERTA
    public function peserta_nomorkartu(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
            "tanggal" => "required|date",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "Peserta/nokartu/" . $request->nomorkartu . "/tglSEP/" . $request->tanggal;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function peserta_nik(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nik" => "required",
            "tanggal" => "required|date",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "Peserta/nik/" . $request->nik . "/tglSEP/" . $request->tanggal;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    // REFERENSI
    public function ref_diagnosa(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "diagnosa" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/diagnosa/" . $request->diagnosa;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_poliklinik(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "poliklinik" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/poli/" . $request->poliklinik;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_faskes(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nama" => "required",
            "jenisfaskes" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/faskes/" . $request->nama . "/" . $request->jenisfaskes;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_dpjp(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "jenispelayanan" => "required",
            "tanggal" => "required|date",
            "kodespesialis" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/dokter/pelayanan/" . $request->jenispelayanan . "/tglPelayanan/" . $request->tanggal . "/Spesialis/" . $request->kodespesialis;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_provinsi(Request $request)
    {
        $url = $this->baseUrl . "referensi/propinsi";
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_kabupaten(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "kodeprovinsi" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/kabupaten/propinsi/" . $request->kodeprovinsi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function ref_kecamatan(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "kodekabupaten" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "referensi/kecamatan/kabupaten/" . $request->kodekabupaten ;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    // RUJUKAN
    public function rujukan_nomor(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "Rujukan/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function rujukan_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }

        $url = $this->baseUrl . "Rujukan/List/Peserta/" . $request->nomorkartu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function rujukan_rs_nomor(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }

        $url = $this->baseUrl . "Rujukan/RS/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);

        return $this->response_decrypt($response, $signature);
    }
    public function rujukan_rs_peserta(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorkartu" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "Rujukan/RS/List/Peserta/" . $request->nomorkartu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function rujukan_jumlah_sep(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "jenisrujukan" => "required",
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "Rujukan/JumlahSEP/" . $request->jenisrujukan . "/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
    }
    public function surat_kontrol_nomor(Request $request)
    {
        // checking request
        $validator = Validator::make(request()->all(), [
            "nomorreferensi" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "RencanaKontrol/noSuratKontrol/" . $request->nomorreferensi;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        return $this->response_decrypt($response, $signature);
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
            return $this->sendError($validator->errors()->first(), null, 201);
        }
        $url = $this->baseUrl . "SEP/2.0/insert";
        $signature = $this->signature();
        $signature['Content-Type'] = 'application/x-www-form-urlencoded';
        $data = [
            "request" => [
                "t_sep" => [
                    "noKartu" => $request->noKartu,
                    "tglSep" => $request->tglSep,
                    "ppkPelayanan" => $request->ppkPelayanan,
                    "jnsPelayanan" => $request->jnsPelayanan,
                    "klsRawat" => [
                        "klsRawatHak" => $request->klsRawatHak,
                        "klsRawatNaik" => "",
                        "pembiayaan" => "",
                        "penanggungJawab" => "",
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
                                    "kdKecamatan" => "",
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
        ];
        $response = Http::withHeaders($signature)->post($url, $data);
        return $this->response_decrypt($response, $signature);
    }
}