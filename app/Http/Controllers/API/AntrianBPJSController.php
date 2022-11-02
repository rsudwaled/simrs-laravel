<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\AntrianController;
use App\Http\Controllers\Controller;
use App\Models\Antrian;
use App\Models\JadwalDokter;
use App\Models\JadwalOperasi;
use App\Models\KunjunganDB;
use App\Models\LayananDB;
use App\Models\LayananDetailDB;
use App\Models\ParamedisDB;
use App\Models\PasienDB;
use App\Models\PenjaminDB;
use App\Models\Poliklinik;
use App\Models\PoliklinikDB;
// use App\Models\SEP;
use App\Models\TarifLayananDetailDB;
use App\Models\TracerDB;
use App\Models\TransaksiDB;
use App\Models\UnitDB;
use Carbon\Carbon;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;
use Mike42\Escpos\PrintConnectors\WindowsPrintConnector;
use Mike42\Escpos\Printer;
use SimpleSoftwareIO\QrCode\Facades\QrCode;

class AntrianBPJSController extends Controller
{
    public $jeniskunjungan = ["Ruukan FKTP", "Rujukan Internal", "Kontrol", "Rujukan Antar RS"];

    public static function signature()
    {
        $cons_id =  env('ANTRIAN_CONS_ID');
        $secretKey = env('ANTRIAN_SECRET_KEY');
        $userkey = env('ANTRIAN_USER_KEY');
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
    // Web Service Antrean - BPJS (Diakses oleh sistem RS)
    public function ref_poli()
    {
        $url = env('ANTRIAN_URL') . "ref/poli";
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
        $response->response = json_decode($decrypt);
        return $response;
    }
    public function ref_dokter()
    {
        $url = env('ANTRIAN_URL') . "ref/dokter";
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
        $response->response = json_decode($decrypt);
        return $response;
    }
    public function ref_jadwal_dokter(Request $request)
    {
        $request['kodepoli'] = $request->kodepoli;
        $request['tanggal'] = $request->tanggalperiksa;
        $url = env('ANTRIAN_URL') . "jadwaldokter/kodepoli/" . $request->kodepoli . "/tanggal/" . $request->tanggal;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        if ($response->metadata->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function update_jadwal_dokter(Request $request)
    {
        $url = env('ANTRIAN_URL') . "jadwaldokter/updatejadwaldokter";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "kodepoli" => $request->kodepoli,
                "kodesubspesialis" => $request->kodesubspesialis,
                "kodedokter" => $request->kodedokter,
                "jadwal" => [
                    [
                        "hari" => "1",
                        "buka" => "08:00",
                        "tutup" => "10:00"
                    ],
                    [
                        "hari" => "2",
                        "buka" => "15:00",
                        "tutup" => "17:00"
                    ]
                ]
            ]),
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function tambah_antrian(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "nomorkartu" =>  "required",
            // "nomorreferensi" =>  "required",
            "nik" =>  "required",
            "nohp" => "required",
            "kodepoli" =>  "required",
            "norm" =>  "required",
            "pasienbaru" =>  "required",
            "tanggalperiksa" =>  "required",
            "kodedokter" =>  "required",
            "jampraktek" =>  "required",
            "jeniskunjungan" => "required",
            "jenispasien" =>  "required",
            "namapoli" =>  "required",
            "namadokter" =>  "required",
            "nomorantrean" =>  "required",
            "angkaantrean" =>  "required",
            "estimasidilayani" =>  "required",
            "sisakuotajkn" =>  "required",
            "kuotajkn" => "required",
            "sisakuotanonjkn" => "required",
            "kuotanonjkn" => "required",
            "keterangan" =>  "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metadata' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = env('ANTRIAN_URL') . "antrean/add";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "kodebooking" => $request->kodebooking,
                "nomorkartu" => $request->nomorkartu,
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
                "jenispasien" => $request->jenispasien,
                "namapoli" => $request->namapoli,
                "namadokter" => $request->namadokter,
                "nomorantrean" => $request->nomorantrean,
                "angkaantrean" => $request->angkaantrean,
                "estimasidilayani" => $request->estimasidilayani,
                "sisakuotajkn" => $request->sisakuotajkn,
                "kuotajkn" => $request->kuotajkn,
                "sisakuotanonjkn" => $request->sisakuotanonjkn,
                "kuotanonjkn" => $request->kuotanonjkn,
                "keterangan" => $request->keterangan,
            ]),
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function update_antrian(Request $request)
    {
        // cek request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "taskid" => "required",
            "waktu" => "required|numeric",
        ]);
        if ($validator->fails()) {
            $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return json_decode(json_encode($response));
        }
        $url = env('ANTRIAN_URL') . "antrean/updatewaktu";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "kodebooking" => $request->kodebooking,
                "taskid" => $request->taskid,
                "waktu" => $request->waktu,
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metadata->code == 200) {
            $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
            $antrian->update([
                "taskid" => $request->taskid,
            ]);
        }
        return $response;
    }
    public function batal_antrian_bpjs(Request $request)
    {
        // cek request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "keterangan" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $url = env('ANTRIAN_URL') . "antrean/batal";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "kodebooking" => $request->kodebooking,
                "keterangan" => $request->keterangan,
            ]),
        ]);
        $response = json_decode($response->getBody());
        return $response;
    }
    public function list_waktu_task(Request $request)
    {
        // cek request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
        ]);
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }
        $url = env('ANTRIAN_URL') . "antrean/getlisttask";
        $signature = $this->signature();
        $client = new Client();
        $response = $client->request('POST', $url, [
            'headers' => $signature,
            'body' => json_encode([
                "kodebooking" => $request->kodebooking,
            ]),
        ]);
        $response = json_decode($response->getBody());
        if ($response->metadata->code == 200) {
            $decrypt = $this->stringDecrypt($signature['decrypt_key'], $response->response);
            $response->response = json_decode($decrypt);
        }
        return $response;
    }
    public function dashboard_tanggal(Request $request)
    {
        // cek request
        $validator = Validator::make(request()->all(), [
            "tanggal" => "required",
            "waktu" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return $response;
        }
        // proses
        $url = env('ANTRIAN_URL') . "dashboard/waktutunggu/tanggal/" . $request->tanggal . "/waktu/" . $request->waktu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)
            ->get($url);
        $response = json_decode($response);
        return $response;
    }
    public function dashboard_bulan(Request $request)
    {
        // cek request
        $validator = Validator::make(request()->all(), [
            "bulan" => "required",
            "tahun" => "required",
            "waktu" => "required",
        ]);
        if ($validator->fails()) {
            $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return $response;
        }
        // proses
        $url = env('ANTRIAN_URL') . "dashboard/waktutunggu/bulan/" . $request->bulan . "/tahun/" . $request->tahun . "/waktu/" . $request->waktu;
        $signature = $this->signature();
        $response = Http::withHeaders($signature)->get($url);
        $response = json_decode($response);
        return $response;
    }
    // Web Service Antrean - RS (Diakses oleh Mobile JKN)
    public function token(Request $request)
    {
        if (Auth::attempt(['username' => $request->header('x-username'), 'password' => $request->header('x-password')])) {
            $user = Auth::user();
            $success['token'] =  $user->createToken('MyApp')->plainTextToken;
            $response = [
                "response" => [
                    "token" => $success['token'],
                ],
                "metadata" => [
                    "code" => 200,
                    "message" => "OK"
                ]
            ];
            return $response;
        } else {
            $response = [
                "metadata" => [
                    "code" => 201,
                    "message" => "Unauthorized (Username dan Password Salah)"
                ]
            ];
            return $response;
        }
    }
    public function auth_token(Request $request)
    {
        $aktif = Auth::check();
        $tokenexpired = 3600;
        if ($aktif == false) {
            if ($request->hasHeader('x-token')) {
                if ($request->hasHeader('x-username')) {
                    $credentials = $request->header('x-token');
                    $token = PersonalAccessToken::findToken($credentials);
                    if (!$token) {
                        return $response = [
                            "metadata" => [
                                "code" => 201,
                                "message" => "Unauthorized (Token Salah)"
                            ]
                        ];
                    } else {
                        $user = $token->tokenable;
                        if (Carbon::now() >  $token->created_at->addMinute($tokenexpired)) {
                            $token->delete();
                            $response = [
                                "metadata" => [
                                    "code" => 201,
                                    "message" => "Token Expired"
                                ]
                            ];
                            return $response;
                        }
                        if ($user->username != $request->header('x-username')) {
                            return $response = [
                                "metadata" => [
                                    "code" => 201,
                                    "message" => "Unauthorized (Username tidak sesuai dengan token)"
                                ]
                            ];
                        } else {
                            return $response = [
                                "metadata" => [
                                    "code" => 200,
                                    "message" => "OK"
                                ]
                            ];
                        }
                    }
                } else {
                    return $response = [
                        "metadata" => [
                            "code" => 201,
                            "message" => "Silahkan isi header dengan x-username"
                        ]
                    ];
                }
            } else {
                return $response = [
                    "metadata" => [
                        "code" => 201,
                        "message" => "Silahkan isi header dengan x-token"
                    ]
                ];
            }
        } else {
            return $response = [
                "metadata" => [
                    "code" => 200,
                    "message" => "OK"
                ]
            ];
        }
    }
    public function status_antrean(Request $request)
    {
        // validator
        $validator = Validator::make(request()->all(), [
            "kodepoli" =>  "required",
            "kodedokter" => "required",
            "tanggalperiksa" => "required|date_format:Y-m-d",
        ]);
        if ($validator->fails()) {
            return json_decode(json_encode(['metadata' => ['code' => 201, 'message' => $validator->errors()->first(),],]));
        }
        // check tanggal
        $time = Carbon::parse($request->tanggalperiksa);
        if ($time->endOfDay()->isPast()) {
            return response()->json(['metadata' => ['code' => 201, 'message' => 'Tanggal periksa sudah terlewat.',],]);
        }
        // cek jadwal
        $jadwal = JadwalDokter::where('hari', $time->dayOfWeek)
            ->where('kodesubspesialis', $request->kodepoli)
            ->where('kodedokter', $request->kodedokter)
            ->first();
        // ada jadwal
        if (isset($jadwal)) {
            $antrian = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa);
            $antrians = $antrian->count();
            $antreanpanggil =  Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('taskid', 4)->first();
            if (isset($antreanpanggil)) {
                $nomorantean = $antreanpanggil->nomorantrian;
            } else {
                $nomorantean = 0;
            }
            $antrianjkn = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('jenispasien', "JKN")->count();
            $antriannonjkn = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('jenispasien', "NON JKN")->count();
            return json_decode(json_encode([
                "response" => [
                    "namapoli" => $jadwal->namasubspesialis,
                    "namadokter" => $jadwal->namadokter,
                    "totalantrean" => $antrians,
                    "sisaantrean" => $jadwal->kapasitaspasien - $antrians,
                    "antreanpanggil" => $nomorantean,
                    "sisakuotajkn" => round($jadwal->kapasitaspasien * 80 / 100) -  $antrianjkn,
                    "kuotajkn" => round($jadwal->kapasitaspasien * 80 / 100),
                    "sisakuotanonjkn" => round($jadwal->kapasitaspasien * 20 / 100) - $antriannonjkn,
                    "kuotanonjkn" =>  round($jadwal->kapasitaspasien * 20 / 100),
                    "keterangan" => "",
                ],
                "metadata" => [
                    "message" => "Ok",
                    "code" => 200
                ]
            ]));
        }
        // tidak ada jadwal
        else {
            return json_decode(json_encode([
                "metadata" => [
                    "code" => 201,
                    "message" => "Tidak ada jadwal dokter " . $request->kodedokter . " di polinkinik " . $request->kodepoli . " dihari tersebut."
                ]
            ]));
        }
    }
    public function status_antrian(Request $request)
    {
        // auth token
        // $auth = $this->auth_token($request);
        // if ($auth['metadata']['code'] != 200) {
        //     return $auth;
        // }
        // check tanggal
        $time = Carbon::parse($request->tanggalperiksa);
        if ($time->endOfDay()->isPast()) {
            return [
                "metadata" => [
                    "code" => 201,
                    "message" => "Tanggal periksa sudah terlewat"
                ]
            ];
        }
        $jadwals = $this->ref_jadwal_dokter($request);
        if (isset($jadwals->response)) {
            $jadwal = collect($jadwals->response)->where('kodedokter', $request->kodedokter)->first();
            if (empty($jadwal)) {
                $response = [
                    "metadata" => [
                        "code" => 201,
                        "message" => "Tidak ada jadwal dokter dihari tersebut."
                    ]
                ];
                return $response;
            }
            $antrian = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa);
            $antrians = $antrian->count();
            $antreanpanggil =  Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('taskid', 4)->first();
            if (isset($antreanpanggil)) {
                $nomorantean = $antreanpanggil->nomorantrian;
            } else {
                $nomorantean = 0;
            }
            $antrianjkn = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('jenispasien', "JKN")->count();
            $antriannonjkn = Antrian::where('kodepoli', $request->kodepoli)
                ->where('tanggalperiksa', $request->tanggalperiksa)
                ->where('jenispasien', "NON-JKN")->count();
            $response = [
                "response" => [
                    "namapoli" => $jadwal->namapoli,
                    "namadokter" => $jadwal->namadokter,
                    "totalantrean" => $antrians,
                    "sisaantrean" => $jadwal->kapasitaspasien - $antrians,
                    "antreanpanggil" => $nomorantean,
                    "sisakuotajkn" => round($jadwal->kapasitaspasien * 80 / 100) -  $antrianjkn,
                    "kuotajkn" => round($jadwal->kapasitaspasien * 80 / 100),
                    "sisakuotanonjkn" => round($jadwal->kapasitaspasien * 20 / 100) - $antriannonjkn,
                    "kuotanonjkn" =>  round($jadwal->kapasitaspasien * 20 / 100),
                    "keterangan" => "Informasi antrian poliklinik",
                ],
                "metadata" => [
                    "message" => "Ok",
                    "code" => 200
                ]
            ];
            return $response;
        } else {
            return  $jadwals;
        }
    }
    public function ambil_antrian(Request $request)
    {
        // auth token
        // $auth = $this->auth_token($request);
        // if ($auth['metadata']['code'] != 200) {
        //     return $auth;
        // }
        // checking request
        $wa = new WhatsappController();
        if (substr($request->nohp, -5) == "@c.us") {
            $request['nohp'] = substr($request->nohp, 0, -5);
        }
        $validator = Validator::make(request()->all(), [
            "nik" => "required|numeric|digits:16",
            "nohp" => "required",
            "kodepoli" => "required",
            "norm" => "required",
            "tanggalperiksa" => "required",
            "kodedokter" => "required",
            "jampraktek" => "required",
            "jeniskunjungan" => "required|numeric",
            // "nomorreferensi" => "numeric",
            "nomorkartu" => "required|numeric|digits:13",
        ]);
        if ($validator->fails()) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " validator : " . $validator->errors()->first();
            $wa->send_notif($request);
            $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
            return $response;
        }
        // check backdate
        if (Carbon::parse($request->tanggalperiksa)->endOfDay()->isPast()) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " backdate";
            $wa->send_notif($request);
            return [
                "metadata" => [
                    "code" => 201,
                    "message" => "Tanggal periksa sudah terlewat"
                ]
            ];
        }
        if (Carbon::parse($request->tanggalperiksa) >  Carbon::now()->addDay(7)) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " overdate";
            $wa->send_notif($request);
            return [
                "metadata" => [
                    "code" => 201,
                    "message" => "Antrian hanya dapat dibuat untuk 7 hari ke kedepan"
                ]
            ];
        }
        // cek duplikasi nik antrian
        $antrian_nik = Antrian::where('tanggalperiksa', $request->tanggalperiksa)
            ->where('nik', $request->nik)
            ->where('kodepoli', $request->kodepoli)
            ->where('taskid', '<=', 4)
            ->count();
        if ($antrian_nik) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " antrian " . $request->method . " nik sama : \nNoRM : " . $request->norm . "\nNIK : " . $request->nik . " Poli : " . $request->kodepoli;
            $wa->send_notif($request);
            return $response = [
                "metadata" => [
                    "message" => "Terdapat antrian dengan nomor NIK yang sama pada tanggal tersebut yang belum selesai.",
                    "code" => 201,
                ],
            ];
        }
        // cek pasien baru hit info pasien baru
        $pasien = PasienDB::where('no_Bpjs',  $request->nomorkartu)->first();
        if (empty($pasien)) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " pasien tidak ditemukan : " . $request->nomorkartu;
            $wa->send_notif($request);
            return $response = [
                "metadata" => [
                    "message" => "Pasien Baru. Silahkan daftar melalui pendaftaran offline",
                    "code" => 202,
                ],
            ];
        }
        // cek no kartu sesuai tidak
        else if ($pasien->no_Bpjs != $request->nomorkartu || $pasien->nik_bpjs != $request->nik) {
            $request['notif'] = "function ambil_antrian error " . $request->method . " data pasien bermasalah : \nNoRM : " . $pasien->no_rm . " = " . $pasien->nama_px . "\nNokartu : " . $request->nomorkartu . " != " . $pasien->no_Bpjs . "\nNik : " . $request->nik . " != " . $pasien->nik_bpjs;
            $wa->send_notif($request);
            return $response = [
                "metadata" => [
                    "message" => "NIK atau Nomor Kartu Tidak Sesuai dengan Data RM, silahkan hubungi petugas pendaftaran untuk memperbaiki data di Rekam Medis",
                    "code" => 201,
                ],
            ];
        }
        // cek pasien lama
        else {
            // cek jika jkn
            if (isset($request->nomorreferensi)) {
                $vclaim = new VclaimBPJSController();
                $request['jenispasien'] = 'JKN';
                // kunjungan kontrol
                if ($request->jeniskunjungan == 3) {
                    $request['nomorsuratkontrol'] = $request->nomorreferensi;
                    $response =  $vclaim->surat_kontrol_nomor($request);
                    if ($response->metaData->code == 200) {
                        $request['nomorrujukan'] = $response->response->sep->provPerujuk->noRujukan;
                        // cek surat kontrol orang lain
                        if ($request->nomorkartu != $response->response->sep->peserta->noKartu) {
                            $request['notif'] = "function ambil_antrian error " . $request->method . " data no kartu pasien bermasalah : " . $request->nomorkartu . " != " . $response->response->sep->peserta->noKartu;
                            $wa->send_notif($request);
                            return [
                                "metadata" => [
                                    "code" => 201,
                                    "message" => "Nomor peserta tidak sesuai dengan surat kontrol."
                                ]
                            ];
                        }
                        if (Carbon::parse($response->response->tglRencanaKontrol) != Carbon::parse($request->tanggalperiksa)) {
                            $request['notif'] = "function ambil_antrian error " . $request->method . " data tanggal rencana kontrol berbeda";
                            $wa->send_notif($request);
                            return [
                                "metadata" => [
                                    "code" => 201,
                                    "message" => "Tanggal periksa tidak sesuai dengan surat kontrol. Silahkan pengajuan perubahan tanggal surat kontrol terlebih dahulu."
                                ]
                            ];
                        }
                    } else {
                        $request['notif'] = "function ambil_antrian error " . $request->method . " surat kontrol " . $response->metaData->message;
                        $wa->send_notif($request);
                        return [
                            "metadata" => [
                                "code" => 201,
                                "message" => $response->metaData->message
                            ]
                        ];
                    }
                }
                // kunjungan rujukan
                else {
                    $request['nomorrujukan'] = $request->nomorreferensi;
                    if ($request->jeniskunjungan == 1) {
                        $response =  $vclaim->rujukan_nomor($request);
                        $request['jenisrujukan'] = 1;
                    } else if ($request->jeniskunjungan == 4) {
                        $response =  $vclaim->rujukan_rs_nomor($request);
                        $request['jenisrujukan'] = 2;
                    }
                    if ($request->method != "OFF") {
                        $jumlah_sep  = $vclaim->rujukan_jumlah_sep($request);
                        // gagal jumlah sep rujukan
                        if ($jumlah_sep->metaData->code != 200) {
                            $request['notif'] = "function ambil_antrian error " . $request->method . " jumlah sep rujukan " . $jumlah_sep->metaData->message;
                            $wa->send_notif($request);
                            return [
                                "metadata" => [
                                    "code" => 201,
                                    "message" => $jumlah_sep->metaData->message
                                ]
                            ];
                        }
                        // berhasil jumlah sep rujukan
                        else {
                            if ($jumlah_sep->response->jumlahSEP == 0) {
                                if ($response->metaData->code == 200) {
                                    // cek rujukan orang lain
                                    if ($request->nomorkartu != $response->response->rujukan->peserta->noKartu) {
                                        $request['notif'] = "function ambil_antrian error " . $request->method . " data no kartu pasien bermasalah : " . $request->nomorkartu . " != " . $response->response->sep->peserta->noKartu;
                                        $wa->send_notif($request);
                                        return [
                                            "metadata" => [
                                                "code" => 201,
                                                "message" => "Nomor peserta tidak sesuai dengan rujukan."
                                            ]
                                        ];
                                    }
                                } else {
                                    $request['notif'] = "function ambil_antrian error " . $request->method . " rujukan " . $response->metaData->message;
                                    $wa->send_notif($request);
                                    return [
                                        "metadata" => [
                                            "code" => 201,
                                            "message" => $response->metaData->message
                                        ]
                                    ];
                                }
                            }
                            // jumlah sep lebih dari 1
                            else {
                                $request['notif'] = "function ambil_antrian error " . $request->method . " rujukan lebih dari 1 kunjungan";
                                $wa->send_notif($request);
                                return [
                                    "metadata" => [
                                        "code" => 201,
                                        "message" => "Mohon maaf Rujukan anda telah digunakan untuk kunjungan pertama kali. Untuk kunjungan selanjutnya silahkan gunakan Surat Kontrol yang dbuat di Poliklinik."
                                    ]
                                ];
                            }
                        }
                    }
                }
            }
            // jika non-jkn harus pilih jenis kunjungan kontrol(3)
            else {
                $request['jenispasien'] = 'NON-JKN';
                // error harus harus pilih jenis kunjungan kontrol(3)
                if ($request->jeniskunjungan != 3) {
                    return [
                        "metadata" => [
                            "message" => "Anda mendaftar tanpa surat Rujukan atau NON-JKN silahkan pilih jenis kunjungan Kontrol(3)",
                            "code" => 201,
                        ],
                    ];
                }
            }
            // ambil data pasien
            $request['norm'] = $pasien->no_rm;
            $request['nama'] = $pasien->nama_px;
            $request['pasienbaru'] = 0;
            // cek jadwal
            // $jadwals = $this->ref_jadwal_dokter($request);
            $jadwals = JadwalDokter::where("kodesubspesialis", $request->kodepoli)->where("hari",  Carbon::parse($request->tanggalperiksa)->dayOfWeek)->get();
            if ($jadwals->count() != 0) {
                $jadwal = $jadwals->where('kodedokter', $request->kodedokter)->first();

                // jika ada jadwal
                if ($jadwal != null) {
                    $kapasitas = $jadwal->kapasitaspasien;
                    $jumlahantridokter = Antrian::where('tanggalperiksa', $request->tanggalperiksa)
                        ->where('kodedokter', $jadwal->kodedokter)
                        ->where('taskid', '!=', 99)
                        ->count();
                    if ($jumlahantridokter >= $kapasitas) {
                        $request['notif'] = "function ambil_antrian error " . $request->method . " jadwal dokter penuh.";
                        $wa->send_notif($request);
                        $response = [
                            "metadata" => [
                                "code" => 201,
                                "message" => "Antrian sudah penuh untuk dokter poliklinik ditanggal tersebut",
                            ]
                        ];
                        return $response;
                    }

                    // ambil data
                    $request['namapoli'] = $jadwal->namasubspesialis;
                    $request['namadokter'] = $jadwal->namadokter;
                }
                // jika dokter tidak ada
                else if ($jadwal == null) {
                    $request['notif'] = "function ambil_antrian error " . $request->method . " null jadwal.";
                    $wa->send_notif($request);
                    $response = [
                        "metadata" => [
                            "code" => 201,
                            "message" => "Tidak ada jadwal dokter poliklinik tersebut ditanggal tersebut",
                        ]
                    ];
                    return $response;
                }
            } else {
                $request['notif'] = "function ambil_antrian error " . $request->method . " tidak ada jadwal kodepoli " . $request->kodepoli . " tanggal periksa " . $request->tanggalperiksa;
                $wa->send_notif($request);
                $response = [
                    "metadata" => [
                        "code" => 201,
                        "message" => "Tidak ada jadwal poliklinik tersebut ditanggal tersebut",
                    ]
                ];
                return $response;
            }
            //  cek nik
            $poli = PoliklinikDB::where('kodesubspesialis', $request->kodepoli)->first();
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
            $request['nomorantrean'] = $request->kodepoli . "-" .  str_pad($antrian_poli + 1, 3, '0', STR_PAD_LEFT);
            $request['angkaantrean'] = $antrians + 1;
            $request['kodebooking'] = strtoupper(uniqid());
            // estimasi
            $timestamp = $request->tanggalperiksa . ' ' . explode('-', $request->jampraktek)[0] . ':00';
            $jadwalbuka = Carbon::createFromFormat('Y-m-d H:i:s', $timestamp, 'Asia/Jakarta')->addMinutes(10 * ($antrian_poli + 1));
            $request['estimasidilayani'] = $jadwalbuka->timestamp * 1000;
            $request['sisakuotajkn'] = round($jadwal->kapasitaspasien * 80 / 100)  -  $antrianjkn - 1;
            $request['kuotajkn'] = round($jadwal->kapasitaspasien * 80 / 100);
            $request['sisakuotanonjkn'] = round($jadwal->kapasitaspasien * 20 / 100) - $antriannonjkn - 1;
            $request['kuotanonjkn'] = round($jadwal->kapasitaspasien * 20 / 100);
            $request['keterangan'] = "Peserta harap 60 menit lebih awal dari jadwal untuk checkin dekat mesin antrian untuk mencetak tiket antrian.";
            //tambah antrian bpjs
            if ($request['method'] == null) {
                $request['method'] = "ON";
            }
            $response = $this->tambah_antrian($request);
            if ($response->metadata->code == 200) {
                // tambah antrian database
                if (isset($suratkontrol)) {
                    $request["nomorsuratkontrol"] = $suratkontrol->noSuratKontrol;
                }
                $antrian = Antrian::create([
                    "kodebooking" => $request->kodebooking,
                    "nomorkartu" => $request->nomorkartu,
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
                    "method" => $request->method,
                    "nomorrujukan" => $request->nomorrujukan,
                    "nomorsuratkontrol" => $request->nomorsuratkontrol,
                    'nomorsep' => $request->nomorsep,
                    "kode_kunjungan" => $request->kode_kunjungan,
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
                    "status_api" => 1,
                    "taskid" => 0,
                    "user" => "System Antrian",
                    "nama" => $request->nama,
                ]);
                // kirim notif offline
                if ($request->method == "OFF") {
                    $wa = new WhatsappController();
                    $request['message'] = "*Antrian Berhasil di Daftarkan*\nAntrian anda berhasil didaftarkan melalui Layanan Online RSUD Waled dengan data sebagai berikut : \n\n*Kode Antrian :* " . $request->kodebooking .  "\n*Angka Antrian :* " . $request->angkaantrean .  "\n*Nomor Antrian :* " . $request->nomorantrean . "\n*Jenis Pasien :* " . $request->jenispasien .  "\n*Jenis Kunjungan :* " . $request->jeniskunjungan .  "\n\n*Nama :* " . $request->nama . "\n*Poliklinik :* " . $request->namapoli  . "\n*Dokter :* " . $request->namadokter  .  "\n*Jam Praktek :* " . $request->jampraktek  .  "\n*Tanggal Periksa :* " . $request->tanggalperiksa . "\n\nTerima kasih. Semoga sehat selalu.\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
                    $request['number'] = $request->nohp;
                    $wa->send_message($request);
                    $response = [
                        "response" => [
                            "nomorantrean" => $request->nomorantrean,
                            "angkaantrean" => $request->angkaantrean,
                            "kodebooking" => $request->kodebooking,
                            "norm" => (string)substr($request->norm, 2),
                            "namapoli" => $request->namapoli,
                            "namadokter" => $request->namadokter,
                            "estimasidilayani" => $request->estimasidilayani,
                            "sisakuotajkn" => $request->sisakuotajkn,
                            "kuotajkn" => $request->kuotajkn,
                            "sisakuotanonjkn" => $request->sisakuotanonjkn,
                            "kuotanonjkn" => $request->kuotanonjkn,
                            "keterangan" => $request->keterangan,
                        ],
                        "metadata" => [
                            "message" => "Ok",
                            "code" => 200
                        ]
                    ];
                    return json_decode(json_encode($response));
                }
                // kirim notif wa
                $qr = QrCode::backgroundColor(255, 255, 51)->format('png')->generate($request->kodebooking, "public/storage/antrian" . $request->kodebooking . ".png");
                $request['filepath'] = public_path("storage/antrian" . $request->kodebooking . ".png");
                $request['caption'] = "Kode booking : " . $request->kodebooking . "\nSilahkan gunakan *QR Code* ini untuk checkin di mesin antrian rawat jalan.";
                $request['number'] = $request->nohp;
                $wa = new WhatsappController();
                $wa->send_filepath($request);
                $wa = new WhatsappController();
                $request['message'] = "*Antrian Berhasil di Daftarkan*\nAntrian anda berhasil didaftarkan melalui Layanan Online RSUD Waled dengan data sebagai berikut : \n\n*Kode Antrian :* " . $request->kodebooking .  "\n*Angka Antrian :* " . $request->angkaantrean .  "\n*Nomor Antrian :* " . $request->nomorantrean . "\n*Jenis Pasien :* " . $request->jenispasien .  "\n*Jenis Kunjungan :* " . $request->jeniskunjungan .  "\n\n*Nama :* " . $request->nama . "\n*Poliklinik :* " . $request->namapoli  . "\n*Dokter :* " . $request->namadokter  .  "\n*Jam Praktek :* " . $request->jampraktek  .  "\n*Tanggal Periksa :* " . $request->tanggalperiksa . "\n\n*Keterangan :* " . $request->keterangan  .  "\nTerima kasih. Semoga sehat selalu.\nUntuk pertanyaan & pengaduan silahkan hubungi :\n*Humas RSUD Waled 08983311118*";
                $request['number'] = $request->nohp;
                $wa->send_message($request);
                $wa = new WhatsappController();
                $request['notif'] = 'Antrian berhasil didaftarkan melalui ' . $request->method . "LINE\n*Nama :* " . $request->nama . "\n*Poliklinik :* " . $request->namapoli .  "\n*Tanggal Periksa :* " . $request->tanggalperiksa . "\n*Jenis Kunjungan :* " . $request->jeniskunjungan;
                $wa->send_notif($request);
                $response = [
                    "response" => [
                        "nomorantrean" => $request->nomorantrean,
                        "angkaantrean" => $request->angkaantrean,
                        "kodebooking" => $request->kodebooking,
                        "norm" => (string)substr($request->norm, 2),
                        "namapoli" => $request->namapoli,
                        "namadokter" => $request->namadokter,
                        "estimasidilayani" => $request->estimasidilayani,
                        "sisakuotajkn" => $request->sisakuotajkn,
                        "kuotajkn" => $request->kuotajkn,
                        "sisakuotanonjkn" => $request->sisakuotanonjkn,
                        "kuotanonjkn" => $request->kuotanonjkn,
                        "keterangan" => $request->keterangan,
                    ],
                    "metadata" => [
                        "message" => "Ok",
                        "code" => 200
                    ]
                ];
                return json_decode(json_encode($response));
            } else {
                return $response;
            }
        }
    }
    public function sisa_antrian(Request $request)
    {
        // auth token
        // $auth = $this->auth_token($request);
        // if ($auth['metadata']['code'] != 200) {
        //     return $auth;
        // }
        $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
        // antrian ditermukan
        if ($antrian) {
            $sisaantrean = Antrian::where('taskid', "<=", 3)
                ->where('tanggalperiksa', $antrian->tanggalperiksa)
                ->where('kodepoli', $antrian->kodepoli)
                ->where('taskid', ">=", 0)
                ->count();
            $sisaantrean = 5;
            $antreanpanggil =  Antrian::where('taskid', "<=", 3)
                ->where('taskid', ">=", 1)
                ->where('tanggalperiksa', $antrian->tanggalperiksa)
                ->first();
            if (empty($antreanpanggil)) {
                $antreanpanggil['nomorantrean'] = 'Tidak Ada';
            }
            $antrian['waktutunggu'] = "10";
            $antrian['keterangan'] = "";
            $response = [
                "response" => [
                    "nomorantrean" => $antrian->nomorantrean,
                    "namapoli" => $antrian->namapoli,
                    "namadokter" => $antrian->namadokter,
                    "sisaantrean" => $sisaantrean,
                    "antreanpanggil" => $antreanpanggil['nomorantrean'],
                    "waktutunggu" => $antrian->waktutunggu * 60 * ($sisaantrean),
                    "keterangan" => $antrian->keterangan,
                ],
                "metadata" => [
                    "message" => "Ok",
                    "code" => 200
                ]
            ];
            return $response;
        }
        // antrian tidak ditermukan
        else {
            return $response = [
                "metadata" => [
                    "message" => "Antrian tidak ditemukan",
                    "code" => 201,
                ],
            ];
        }
    }
    public function info_pasien_baru(Request $request)
    {
        // auth token
        $auth = $this->auth_token($request);
        if ($auth['metadata']['code'] != 200) {
            return $auth;
        }
        // checking request
        $validator = Validator::make(request()->all(), [
            "nik" => "required|digits:16",
            "nomorkartu" => "required|digits:13",
            "nomorkk" => "required",
            "nama" => "required",
            "jeniskelamin" => "required",
            "tanggallahir" => "required",
            "nohp" => "required",
            "alamat" => "required",
            "kodeprop" => "required",
            "namaprop" => "required",
            "kodedati2" => "required",
            "namadati2" => "required",
            "kodekec" => "required",
            "namakec" => "required",
            "kodekel" => "required",
            "namakel" => "required",
            "rw" => "required",
            "rt" => "required",
        ]);
        if ($validator->fails()) {
            return [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $pasien = PasienDB::where('nik_bpjs', $request->nik)->first();
        // cek jika pasien baru
        if (empty($pasien)) {
            // proses pendaftaran baru
            // try {
            //     // checking norm terakhir
            //     $pasien_terakhir = PasienDB::latest()->first()->no_rm;
            //     $request['status'] = 1;
            //     $request['norm'] = $pasien_terakhir + 1;
            //     // insert pasien
            //     PasienDB::create(
            //         [
            //             "no_Bpjs" => $request->nomorkartu,
            //             "nik_bpjs" => $request->nik,
            //             "no_rm" => $request->norm,
            //             // "nomorkk" => $request->nomorkk,
            //             "nama_px" => $request->nama,
            //             "jenis_kelamin" => $request->jeniskelamin,
            //             "tgl_lahir" => $request->tanggallahir,
            //             "no_tlp" => $request->nohp,
            //             "alamat" => $request->alamat,
            //             "kode_propinsi" => $request->kodeprop,
            //             // "namaprop" => $request->namaprop,
            //             "kode_kabupaten" => $request->kodedati2,
            //             // "namadati2" => $request->namadati2,
            //             "kode_kecamatan" => $request->kodekec,
            //             // "namakec" => $request->namakec,
            //             "kode_desa" => $request->kodekel,
            //             // "namakel" => $request->namakel,
            //             // "rw" => $request->rw,
            //             // "rt" => $request->rt,
            //             // "status" => $request->status,
            //         ]
            //     );
            //     return  $response = [
            //         "response" => [
            //             "norm" => $request->norm,
            //         ],
            //         "metadata" => [
            //             "message" => "Ok",
            //             "code" => 200,
            //         ],
            //     ];
            // } catch (\Throwable $th) {
            //     $response = [
            //         "metadata" => [
            //             "message" => "Gagal Error Code " . $th->getMessage(),
            //             "code" => 201,
            //         ],
            //     ];
            //     return $response;
            // }
            return [
                'metadata' => [
                    'code' => 201,
                    'message' => 'Mohon maaf untuk pasien baru tidak bisa didaftarkan secara online. Silahkan daftar secara offline dengan datang ke Rumah Sakit',
                ],
            ];
        }
        // cek jika pasien lama
        else {
            $pasien->update([
                "no_Bpjs" => $request->nomorkartu,
                // "nik_bpjs" => $request->nik,
                // "no_rm" => $request->norm,
                "nomorkk" => $request->nomorkk,
                "nama_px" => $request->nama,
                "jenis_kelamin" => $request->jeniskelamin,
                "tgl_lahir" => $request->tanggallahir,
                "no_tlp" => $request->nohp,
                "alamat" => $request->alamat,
                "kode_propinsi" => $request->kodeprop,
                "namaprop" => $request->namaprop,
                "kode_kabupaten" => $request->kodedati2,
                "namadati2" => $request->namadati2,
                "kode_kecamatan" => $request->kodekec,
                "namakec" => $request->namakec,
                "kode_desa" => $request->kodekel,
                "namakel" => $request->namakel,
                "rw" => $request->rw,
                "rt" => $request->rt,
                // "status" => $request->status,
            ]);
            return $response = [
                "response" => [
                    "norm" => $pasien->no_rm,
                ],
                "metadata" => [
                    "message" => "Ok",
                    "code" => 200,
                ],
            ];
        }
    }
    public function batal_antrian(Request $request)
    {
        // auth token
        // $auth = $this->auth_token($request);
        // if ($auth['metadata']['code'] != 200) {
        //     return $auth;
        // }
        // cek request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "keterangan" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
        // cari antrian
        if ($antrian) {
            $response = $this->batal_antrian_bpjs($request);
            // kirim notif wa
            $wa = new WhatsappController();
            $request['message'] = "Kode antrian " . $antrian->kodebooking . " telah dibatakan karena :\n" . $request->keterangan;
            $request['number'] = $antrian->nohp;
            $wa->send_message($request);
            $antrian->update([
                "taskid" => 99,
                "status_api" => 1,
                "keterangan" => $request->keterangan,
            ]);
            return $response;
        }
        // antrian tidak ditemukan
        else {
            return $response = [
                "metadata" => [
                    "message" => "Antrian tidak ditemukan",
                    "code" => 201,
                ],
            ];
        }
    }
    public function checkin_antrian(Request $request)
    {
        // cek printer
        try {
            $connector = new WindowsPrintConnector(env('PRINTER_CHECKIN'));
            $printer = new Printer($connector);
            $printer->close();
        } catch (\Throwable $th) {
            $response = [
                "metadata" => [
                    "message" => "Printer mesin antrian mati",
                    "code" => 201,
                ],
            ];
            return $response;
        }
        // checking request
        $validator = Validator::make(request()->all(), [
            "kodebooking" => "required",
            "waktu" => "required",
        ]);
        if ($validator->fails()) {
            return $response = [
                'metaData' => [
                    'code' => 400,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
        // jika antrian ditemukan
        if (isset($antrian)) {
            // check backdate
            if (!Carbon::parse($antrian->tanggalperiksa)->isToday()) {
                return [
                    "metadata" => [
                        "code" => 201,
                        "message" => "Tanggal periksa bukan hari ini."
                    ]
                ];
            }
            $now = Carbon::now();
            $unit = UnitDB::firstWhere('KDPOLI', $antrian->kodepoli);
            $tarifkarcis = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_karcis);
            $tarifadm = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_adm);

            if ($antrian->taskid == 3) {
                $this->print_ulang($request);
                return [
                    "metadata" => [
                        "message" => "Printer Ulang",
                        "code" => 201,
                    ],
                ];
            }
            if ($antrian->pasienbaru) {
                $request['pasienbaru_print'] = 'BARU';
            } else {
                $request['pasienbaru_print'] = 'LAMA';
            }
            // jika pasien jkn
            if ($antrian->jenispasien == "JKN") {
                $request['status_api'] = 1;
                $request['taskid'] = 3;
                $request['keterangan'] = "Untuk pasien peserta JKN silahkan dapat langsung menunggu ke POLIKINIK " . $antrian->namapoli;
                $request['noKartu'] = $antrian->nomorkartu;
                $request['tglSep'] = Carbon::createFromTimestamp($request->waktu / 1000)->format('Y-m-d');
                $request['noMR'] = $antrian->norm;
                $request['norm'] = $antrian->norm;
                $request['nik'] = $antrian->nik;
                $request['nohp'] = $antrian->nohp;
                $request['kodedokter'] = $antrian->kodedokter;
                // insert sep
                $vclaim = new VclaimBPJSController();
                // daftar pake surat kontrol
                if ($antrian->jeniskunjungan == 3) {
                    $request['nomorreferensi'] = $antrian->nomorsuratkontrol;
                    $suratkontrol = $vclaim->surat_kontrol_nomor($request);
                    // berhasil get surat kontrol
                    if ($suratkontrol->metaData->code == 200) {
                        $request['nomorsuratkontrol'] = $antrian->nomorsuratkontrol;
                        if ($suratkontrol->response->sep->jnsPelayanan == "Rawat Jalan") {
                            $request['nomorrujukan'] = $suratkontrol->response->sep->provPerujuk->noRujukan;
                            $request['jeniskunjungan_print'] = 'KONTROL';
                            $request['nomorreferensi'] = $antrian->nomorrujukan;
                            $data = $vclaim->rujukan_nomor($request);
                            if ($data->metaData->code != 200) {
                                $data = $vclaim->rujukan_rs_nomor($request);
                            }
                            // berhasil get rujukan
                            if ($data->metaData->code == 200) {
                                $rujukan = $data->response->rujukan;
                                $peserta = $rujukan->peserta;
                                $diganosa = $rujukan->diagnosa;
                                $tujuan = $rujukan->poliRujukan;
                                $penjamin = PenjaminDB::where('nama_penjamin_bpjs', $peserta->jenisPeserta->keterangan)->first(); // get peserta
                                $request['kodepenjamin'] = $penjamin->kode_penjamin_simrs; // get peserta
                                // tujuan rujukan
                                $request['ppkPelayanan'] = "1018R001";
                                $request['jnsPelayanan'] = "2";
                                // peserta
                                $request['klsRawatHak'] = $peserta->hakKelas->kode; // get peserta
                                $request['klsRawatNaik'] = ""; // get peserta
                                // $request['pembiayaan'] = $peserta->jenisPeserta->kode;
                                // $request['penanggungJawab'] =  $peserta->jenisPeserta->keterangan;
                                // asal rujukan
                                $request['asalRujukan'] = $data->response->asalFaskes; // get surat kontrol
                                $request['tglRujukan'] = $rujukan->tglKunjungan; // get surat kontrol
                                $request['noRujukan'] =   $rujukan->noKunjungan; // get surat kontrol
                                $request['ppkRujukan'] = $rujukan->provPerujuk->kode; // get surat kontrol
                                // diagnosa
                                $request['catatan'] =  $diganosa->nama; // get surat kontrol
                                $request['diagAwal'] =  $diganosa->kode; // get surat kontrol
                                // poli tujuan
                                $request['tujuan'] =  $antrian->kodepoli; // get antrian
                                $request['eksekutif'] =  0;
                                // dpjp
                                $request['tujuanKunj'] = "2";
                                $request['flagProcedure'] = "";
                                $request['kdPenunjang'] = "";
                                $request['assesmentPel'] = "2";
                                $request['noSurat'] = $request->nomorsuratkontrol; // get antrian
                                $request['kodeDPJP'] = $suratkontrol->response->kodeDokter;
                                $request['dpjpLayan'] =  $suratkontrol->response->kodeDokter;
                            }
                            // gagal get rujukan
                            else {
                                return [
                                    "metadata" => [
                                        "message" => $data->metaData->message,
                                        "code" => 201,
                                    ],
                                ];
                            }
                        } else {
                            $request['nomorkartu'] = $antrian->nomorkartu;
                            $data = $vclaim->peserta_nomorkartu($request);
                            // berhasil get rujukan
                            if ($data->metaData->code == 200) {
                                $peserta = $data->response->peserta;
                                $diagnosa = $suratkontrol->response->sep->diagnosa;
                                $asalRujukan = $suratkontrol->response->sep->provPerujuk->asalRujukan;
                                $tglRujukan = $suratkontrol->response->sep->provPerujuk->tglRujukan;
                                $noRujukan = $suratkontrol->response->sep->noSep;
                                $ppkRujukan = $suratkontrol->response->sep->provPerujuk->kdProviderPerujuk;
                                $penjamin = PenjaminDB::where('nama_penjamin_bpjs', $peserta->jenisPeserta->keterangan)->first(); // get peserta
                                $request['kodepenjamin'] = $penjamin->kode_penjamin_simrs; // get peserta
                                // tujuan rujukan
                                $request['ppkPelayanan'] = "1018R001";
                                $request['jnsPelayanan'] = "2";
                                // peserta
                                $request['klsRawatHak'] = $peserta->hakKelas->kode; // get peserta
                                $request['klsRawatNaik'] = ""; // get peserta
                                // $request['pembiayaan'] = $peserta->jenisPeserta->kode;
                                // $request['penanggungJawab'] =  $peserta->jenisPeserta->keterangan;
                                // asal rujukan
                                $request['asalRujukan'] = $asalRujukan; // get surat kontrol
                                $request['tglRujukan'] = $tglRujukan; // get surat kontrol
                                $request['noRujukan'] =   $noRujukan; // get surat kontrol
                                $request['ppkRujukan'] = $ppkRujukan; // get surat kontrol
                                // diagnosa
                                $request['catatan'] =  $diagnosa; // get surat kontrol
                                $request['diagAwal'] = str_replace(" ", "", explode('-', $diagnosa)[0]);
                                // poli tujuan
                                $request['tujuan'] =  $antrian->kodepoli; // get antrian
                                $request['eksekutif'] =  0;
                                // dpjp
                                $request['tujuanKunj'] = "0";
                                $request['flagProcedure'] = "";
                                $request['kdPenunjang'] = "";
                                $request['assesmentPel'] = "";
                                $request['noSurat'] = $request->nomorsuratkontrol; // get antrian
                                $request['kodeDPJP'] = $suratkontrol->response->kodeDokter;
                                $request['dpjpLayan'] =  $suratkontrol->response->kodeDokter;
                            }
                        }
                        $sep = $vclaim->insert_sep($request);
                    }
                    // gagal get surat kontrol
                    else {
                        return [
                            "metadata" => [
                                "message" => $suratkontrol->metaData->message,
                                "code" => 201,
                            ],
                        ];
                    }
                }
                // daftar pake rujukan
                else {
                    $request['nomorrujukan'] = $antrian->nomorreferensi;
                    $request['nomorreferensi'] = $antrian->nomorreferensi;
                    $request['jeniskunjungan_print'] = 'RUJUKAN';
                    if ($antrian->jeniskunjungan == 4) {
                        $data = $vclaim->rujukan_rs_nomor($request);
                    } else  if ($antrian->jeniskunjungan == 1) {
                        $data = $vclaim->rujukan_nomor($request);
                    }
                    // berhasil get rujukan
                    if ($data->metaData->code == 200) {
                        $rujukan = $data->response->rujukan;
                        $peserta = $rujukan->peserta;
                        $diganosa = $rujukan->diagnosa;
                        $tujuan = $rujukan->poliRujukan;
                        $penjamin = PenjaminDB::where('nama_penjamin_bpjs', $peserta->jenisPeserta->keterangan)->first();
                        $request['kodepenjamin'] = $penjamin->kode_penjamin_simrs;
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
                        $request['tujuan'] =  $antrian->kodepoli;
                        $request['eksekutif'] =  0;
                        // dpjp
                        $request['tujuanKunj'] = "0";
                        $request['flagProcedure'] = "";
                        $request['kdPenunjang'] = "";
                        $request['assesmentPel'] = "";
                        // $request['noSurat'] = "";
                        $request['kodeDPJP'] = "";
                        $request['dpjpLayan'] = $antrian->kodedokter;
                        $request['noTelp'] = $antrian->nohp;
                        $request['user'] = "Mesin Antrian";
                    }
                    // gagal get rujukan
                    else {
                        return [
                            "metadata" => [
                                "message" => $data->metaData->message,
                                "code" => 201,
                            ],
                        ];
                    }
                    // create sep
                    $sep = $vclaim->sep_insert($request);
                }
                // berhasil buat sep
                if ($sep->metaData->code == 200) {
                    // update antrian sep
                    $request["nomorsep"] = $sep->response->sep->noSep;
                    $antrian->update([
                        "nomorsep" => $request->nomorsep
                    ]);
                    // print sep
                    $print_sep = new AntrianController();
                    $print_sep->print_sep($request, $sep);
                }
                // gagal buat sep
                else {
                    return [
                        "metadata" => [
                            "message" => "Gagal Buat SEP : " . $sep->metaData->message,
                            "code" => 201,
                        ],
                    ];
                }
                // rj jkn tipe transaki 2 status layanan 2 status layanan detail opn
                $tipetransaksi = 2;
                $statuslayanan = 2;
                // rj jkn masuk ke tagihan penjamin
                $tagihanpenjamin_karcis = $tarifkarcis->TOTAL_TARIF_NEW;
                $tagihanpenjamin_adm = $tarifadm->TOTAL_TARIF_NEW;
                $totalpenjamin =  $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW;
                $tagihanpribadi_karcis = 0;
                $tagihanpribadi_adm = 0;
                $totalpribadi =  0;
            }
            // jika pasien non jkn
            else {
                $request['taskid'] = 3;
                $request['status_api'] = 0;
                $request['kodepenjamin'] = "P01";
                $request['jeniskunjungan_print'] = 'KUNJUNGAN UMUM';
                $request['keterangan'] = "Untuk pasien peserta NON-JKN silahkan menunggu panggilan di Loket Pembayaran samping BJB";
                // rj umum tipe transaki 1 status layanan 1 status layanan detail opn
                $tipetransaksi = 1;
                $statuslayanan = 1;
                // rj umum masuk ke tagihan pribadi
                $tagihanpenjamin_karcis = 0;
                $tagihanpenjamin_adm = 0;
                $totalpenjamin =  0;

                $tagihanpribadi_karcis = $tarifkarcis->TOTAL_TARIF_NEW;
                $tagihanpribadi_adm = $tarifadm->TOTAL_TARIF_NEW;
                $totalpribadi = $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW;
            }
            // insert simrs create kunjungan
            try {
                $paramedis = ParamedisDB::firstWhere('kode_dokter_jkn', $antrian->kodedokter);
                // hitung counter kunjungan
                $kunjungan = KunjunganDB::where('no_rm', $antrian->norm)->orderBy('counter', 'DESC')->first();
                if (empty($kunjungan)) {
                    $counter = 1;
                } else {
                    $counter = $kunjungan->counter + 1;
                }
                // insert ts kunjungan status 8
                KunjunganDB::create(
                    [
                        'counter' => $counter,
                        'no_rm' => $antrian->norm,
                        'kode_unit' => $unit->kode_unit,
                        'tgl_masuk' => $now,
                        'kode_paramedis' => $paramedis->kode_paramedis,
                        'status_kunjungan' => 8,
                        'prefix_kunjungan' => $unit->prefix_unit,
                        'kode_penjamin' => $request->kodepenjamin,
                        'pic' => 1319,
                        'id_alasan_masuk' => 1,
                        'kelas' => 3,
                        'hak_kelas' => $request->klsRawatHak,
                        'no_sep' =>  $request->nomorsep,
                        'no_rujukan' => $antrian->nomorrujukan,
                        'diagx' =>   $request->catatan,
                        'created_at' => $now,
                        'keterangan2' => 'MESIN_2',
                    ]
                );
                $kunjungan = KunjunganDB::where('no_rm', $antrian->norm)->where('counter', $counter)->first();
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
                        'pic' => '1319',
                        'keterangan' => 'Layanan header melalui antrian sistem',
                    ]
                );
                //  insert layanan header dan detail karcis admin konsul 25 + 5 = 30
                //  DET tahun bulan `tanggal b`aru urutan 6 digit kanan
                //  insert layanan detail karcis
                $layanandet = LayananDetailDB::orderBy('tgl_layanan_detail', 'DESC')->first();
                $nomorlayanandet = substr($layanandet->id_layanan_detail, 9) + 1;
                $karcis = LayananDetailDB::create(
                    [
                        'id_layanan_detail' => "DET" . $now->format('y') . $now->format('m') . $now->format('d')  . $nomorlayanandet,
                        'row_id_header' => $layananbaru->id,
                        'kode_layanan_header' => $layananbaru->kode_layanan_header,
                        'kode_tarif_detail' => $tarifkarcis->KODE_TARIF_DETAIL,
                        'total_tarif' => $tarifkarcis->TOTAL_TARIF_NEW,
                        'jumlah_layanan' => 1,
                        'tagihan_pribadi' => $tagihanpribadi_karcis,
                        'tagihan_penjamin' => $tagihanpenjamin_karcis,
                        'total_layanan' => $tarifkarcis->TOTAL_TARIF_NEW,
                        'grantotal_layanan' => $tarifkarcis->TOTAL_TARIF_NEW,
                        'kode_dokter1' => $paramedis->kode_paramedis, // ambil dari mt paramdeis
                        'tgl_layanan_detail' =>  $now,
                        'status_layanan_detail' => "OPN",
                        'tgl_layanan_detail_2' =>  $now,
                    ]
                );
                //  insert layanan detail admin
                $layanandet = LayananDetailDB::orderBy('tgl_layanan_detail', 'DESC')->first();
                $nomorlayanandet = substr($layanandet->id_layanan_detail, 9) + 1;
                $adm = LayananDetailDB::create(
                    [
                        'id_layanan_detail' => "DET" . $now->format('y') . $now->format('m') . $now->format('d')  . $nomorlayanandet,
                        'row_id_header' => $layananbaru->id,
                        'kode_layanan_header' => $layananbaru->kode_layanan_header,
                        'kode_tarif_detail' => $tarifadm->KODE_TARIF_DETAIL,
                        'total_tarif' => $tarifadm->TOTAL_TARIF_NEW,
                        'jumlah_layanan' => 1,
                        'tagihan_pribadi' =>  $tagihanpribadi_adm,
                        'tagihan_penjamin' =>  $tagihanpenjamin_adm,
                        'total_layanan' => $tarifadm->TOTAL_TARIF_NEW,
                        'grantotal_layanan' => $tarifadm->TOTAL_TARIF_NEW,
                        'kode_dokter1' => 0,
                        'tgl_layanan_detail' =>  $now,
                        'status_layanan_detail' => "OPN",
                        'tgl_layanan_detail_2' =>  $now,
                    ]
                );
                //  update layanan header total tagihan
                $layananbaru->update([
                    'total_layanan' => $tarifkarcis->TOTAL_TARIF_NEW + $tarifadm->TOTAL_TARIF_NEW,
                    'tagihan_pribadi' => $totalpribadi,
                    'tagihan_penjamin' => $totalpenjamin,
                ]);
            } catch (\Throwable $th) {
                return [
                    "metadata" => [
                        "message" => "Error Create Kunjungan SIMRS : " . $th->getMessage(),
                        "code" => 201,
                    ],
                ];
            }
            // update antrian bpjs
            $response = $this->update_antrian($request);
            // jika antrian berhasil diupdate di bpjs
            if ($response->metadata->code == 200) {
                // update antrian kunjungan
                try {
                    $kunjungan->update([
                        'status_kunjungan' => 1,
                    ]);
                    $antrian->update([
                        "kode_kunjungan" => $kunjungan->kode_kunjungan,
                    ]);
                    // insert tracer tc_tracer_header
                    $tracerbaru = TracerDB::create([
                        'kode_kunjungan' => $kunjungan->kode_kunjungan,
                        'tgl_tracer' => $now->format('Y-m-d'),
                        'id_status_tracer' => 1,
                        'cek_tracer' => "N",
                    ]);
                } catch (\Throwable $th) {
                    //throw $th;
                    return [
                        "metadata" => [
                            "message" => "Error Update Kunjungan Antrian : " . $th->getMessage(),
                            "code" => 201,
                        ],
                    ];
                }
                // update antrian print tracer wa
                try {
                    $antrian->update([
                        "taskid" => $request->taskid,
                        "status_api" => $request->status_api,
                        "keterangan" => $request->keterangan,
                        "taskid1" => $now,
                    ]);
                    // print antrian
                    $print_karcis = new AntrianController();
                    $request['tarifkarcis'] = $tarifkarcis->TOTAL_TARIF_NEW;
                    $request['tarifadm'] = $tarifadm->TOTAL_TARIF_NEW;
                    $request['norm'] = $antrian->norm;
                    $request['nama'] = $antrian->nama;
                    $request['nik'] = $antrian->nik;
                    $request['nomorkartu'] = $antrian->nomorkartu;
                    $request['nohp'] = $antrian->nohp;
                    $request['nomorrujukan'] = $antrian->nomorrujukan;
                    $request['nomorsuratkontrol'] = $antrian->nomorsuratkontrol;
                    $request['namapoli'] = $antrian->namapoli;
                    $request['namadokter'] = $antrian->namadokter;
                    $request['jampraktek'] = $antrian->jampraktek;
                    $request['tanggalperiksa'] = $antrian->tanggalperiksa;
                    $request['jenispasien'] = $antrian->jenispasien;
                    $request['nomorantrean'] = $antrian->nomorantrean;
                    $request['lokasi'] = $antrian->lokasi;
                    $request['angkaantrean'] = $antrian->angkaantrean;
                    $request['lantaipendaftaran'] = $antrian->lantaipendaftaran;
                    $print_karcis->print_karcis($request, $kunjungan);
                    // notif wa
                    $wa = new WhatsappController();
                    $request['message'] = "Antrian dengan kode booking " . $antrian->kodebooking . " telah melakukan checkin.\n\n" . $request->keterangan;
                    $request['number'] = $antrian->nohp;
                    $wa->send_message($request);
                } catch (\Throwable $th) {
                    return [
                        "metadata" => [
                            "message" => "Error Update Antrian : " . $th->getMessage(),
                            "code" => 201,
                        ],
                    ];
                }
            }
            return $response;
        }
        // jika antrian tidak ditemukan
        else {
            return [
                "metadata" => [
                    "message" => "Kode booking tidak ditemukan",
                    "code" => 201,
                ],
            ];
        }
    }
    public function print_ulang(Request $request)
    {
        $antrian = Antrian::firstWhere('kodebooking', $request->kodebooking);
        $unit = UnitDB::firstWhere('KDPOLI', $antrian->kodepoli);
        $tarifkarcis = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_karcis);
        $tarifadm = TarifLayananDetailDB::firstWhere('KODE_TARIF_DETAIL', $unit->kode_tarif_adm);
        if ($antrian->taskid == 3) {
            // print antrian
            $print_karcis = new AntrianController();
            $request['tarifkarcis'] = $tarifkarcis->TOTAL_TARIF_NEW;
            $request['tarifadm'] = $tarifadm->TOTAL_TARIF_NEW;
            $request['norm'] = $antrian->norm;
            $request['nama'] = $antrian->nama;
            $request['nik'] = $antrian->nik;
            $request['nomorkartu'] = $antrian->nomorkartu;
            $request['nohp'] = $antrian->nohp;
            $request['nomorrujukan'] = $antrian->nomorrujukan;
            $request['nomorsuratkontrol'] = $antrian->nomorsuratkontrol;
            $request['namapoli'] = $antrian->namapoli;
            $request['namadokter'] = $antrian->namadokter;
            $request['jampraktek'] = $antrian->jampraktek;
            $request['tanggalperiksa'] = $antrian->tanggalperiksa;
            $request['jenispasien'] = $antrian->jenispasien;
            $request['nomorantrean'] = $antrian->nomorantrean;
            $request['lokasi'] = $antrian->lokasi;
            $request['angkaantrean'] = $antrian->angkaantrean;
            $request['lantaipendaftaran'] = $antrian->lantaipendaftaran;
            $kunjungan = KunjunganDB::firstWhere('kode_kunjungan', $antrian->kode_kunjungan);
            $print_karcis->print_karcis($request, $kunjungan);
            return [
                "metadata" => [
                    "message" => "Print ulang sukses.",
                    "code" => 200,
                ],
            ];
        }
    }
    public function jadwal_operasi_rs(Request $request)
    {
        // auth token
        $auth = $this->auth_token($request);
        if ($auth['metadata']['code'] != 200) {
            return $auth;
        }
        // checking request
        $validator = Validator::make(request()->all(), [
            "tanggalawal" => "required",
            "tanggalakhir" => "required",
        ]);
        if ($validator->fails()) {
            return [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        // end auth token
        $jadwalops = JadwalOperasi::whereBetween('tanggaloperasi', [$request->tanggalawal, $request->tanggalakhir])->get();
        $jadwals = [];
        foreach ($jadwalops as  $jadwalop) {
            if ($jadwalop->terlaksana == "0") {
                $terlaksana = "Belum";
            } else {
                $terlaksana = "Sudah";
            }
            $jadwals[] = [
                "kodebooking" => $jadwalop->kodebooking,
                "tanggaloperasi" => $jadwalop->tanggaloperasi,
                "jenistindakan" => $jadwalop->jenistindakan,
                "kodepoli" => $jadwalop->kodepoli,
                "namapoli" => $jadwalop->namapoli,
                "terlaksana" => $terlaksana,
                "nopeserta" => $jadwalop->nopeserta,
                "lastupdate" => Carbon::parse($jadwalop->updated_at)->format('Y-m-d H:i:s'),
            ];
        }
        $response = [
            "response" => [
                "list" => $jadwals
            ],
            "metadata" => [
                "message" => "Ok",
                "code" => 200
            ]
        ];
        return $response;
    }
    public function jadwal_operasi_pasien(Request $request)
    {
        // auth token
        $auth = $this->auth_token($request);
        if ($auth['metadata']['code'] != 200) {
            return $auth;
        }
        // checking request
        $validator = Validator::make(request()->all(), [
            "nopeserta" => "required|digits:13",
        ]);
        if ($validator->fails()) {
            return [
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ];
        }
        // end auth token
        $jadwalops = JadwalOperasi::where('nopeserta', $request->nopeserta)
            ->where('tanggaloperasi', '>=', Carbon::now()->format('Y-m-d'))
            ->get();

        $jadwals = [];
        foreach ($jadwalops as  $jadwalop) {
            if ($jadwalop->terlaksana == "0") {
                $terlaksana = "Belum";
            } else {
                $terlaksana = "Sudah";
            }
            $jadwals[] = [
                "kodebooking" => $jadwalop->kodebooking,
                "tanggaloperasi" => $jadwalop->tanggaloperasi,
                "jenistindakan" => $jadwalop->jenistindakan,
                "kodepoli" => $jadwalop->kodepoli,
                "namapoli" => $jadwalop->namapoli,
                "terlaksana" => $terlaksana,
                "nopeserta" => $jadwalop->nopeserta,
                "lastupdate" => Carbon::parse($jadwalop->updated_at)->format('Y-m-d H:i:s'),
            ];
        }
        $response = [
            "response" => [
                "list" => $jadwals
            ],
            "metadata" => [
                "message" => "Ok",
                "code" => 200
            ]
        ];
        return $response;
    }
}
