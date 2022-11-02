<?php

use App\Http\Controllers\AntrianController;
use App\Http\Controllers\API\AntrianBPJSController;
use App\Http\Controllers\API\VclaimBPJSController;
use App\Http\Controllers\API\WhatsappController;
use App\Http\Controllers\PasienController;
use App\Http\Controllers\VclaimController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::prefix('vclaim')->group(function () {
    Route::get('caripasien', [PasienController::class, 'caripasien'])->name('api.caripasien');
});

Route::prefix('antrian')->group(function () {
    Route::get('signature', [AntrianBPJSController::class, 'signature']);
    Route::get('ref_poli', [AntrianBPJSController::class, 'ref_poli']);
    Route::get('ref_dokter', [AntrianBPJSController::class, 'ref_dokter']);
    Route::get('ref_jadwal', [AntrianBPJSController::class, 'ref_jadwal_dokter']);
    Route::post('ref_updatejadwal', [AntrianBPJSController::class, 'update_jadwal_dokter']);
    Route::post('tambah', [AntrianBPJSController::class, 'tambah_antrian']);
    Route::post('update', [AntrianBPJSController::class, 'update_antrian']);
    Route::post('batal', [AntrianBPJSController::class, 'batal_antrian_bpjs']);
    Route::post('listtask', [AntrianBPJSController::class, 'list_waktu_task']);
    Route::get('dashboard_tanggal', [AntrianBPJSController::class, 'dashboard_tanggal']);
    Route::get('dashboard_bulan', [AntrianBPJSController::class, 'dashboard_bulan']);

    Route::get('status_antrean', [AntrianBPJSController::class, 'status_antrean'])->name('api.status_antrean');
    Route::post('ambil_antrean', [AntrianBPJSController::class, 'ambil_antrean'])->name('api.ambil_antrean');
});

Route::get('token', [AntrianBPJSController::class, 'token']);
Route::prefix('wsrs')->group(function () {
    Route::post('ambil_antrian', [AntrianBPJSController::class, 'ambil_antrian']);
    Route::post('status_antrian', [AntrianBPJSController::class, 'status_antrian']);
    Route::post('sisa_antrian', [AntrianBPJSController::class, 'sisa_antrian']);
    Route::post('batal_antrian', [AntrianBPJSController::class, 'batal_antrian']);
    Route::post('checkin_antrian', [AntrianBPJSController::class, 'checkin_antrian']);
    Route::post('info_pasien_baru', [AntrianBPJSController::class, 'info_pasien_baru']);
    Route::post('jadwal_operasi_rs', [AntrianBPJSController::class, 'jadwal_operasi_rs']);
    Route::post('jadwal_operasi_pasien', [AntrianBPJSController::class, 'jadwal_operasi_pasien']);

    Route::post('pasien_pendaftaran', [AntrianBPJSController::class, 'pasien_pendaftaran']);
    Route::post('panggil_pendaftaran', [AntrianBPJSController::class, 'panggil_pendaftaran']);
    Route::post('update_pendaftaran_offline', [AntrianBPJSController::class, 'update_pendaftaran_offline']);
    Route::post('update_pendaftaran_online', [AntrianBPJSController::class, 'update_pendaftaran_online']);
});

Route::prefix('vclaim')->group(function () {
    // ref
    Route::get('signature', [VclaimBPJSController::class, 'signature'])->name('signature');
    Route::get('ref_provinsi', [VclaimBPJSController::class, 'ref_provinsi'])->name('ref_provinsi');
    Route::post('ref_kabupaten', [VclaimBPJSController::class, 'ref_kabupaten'])->name('ref_kabupaten');
    Route::post('ref_kecamatan', [VclaimBPJSController::class, 'ref_kecamatan'])->name('ref_kecamatan');
    // monitoring
    Route::get('monitoring_pelayanan_peserta', [VclaimBPJSController::class, 'monitoring_pelayanan_peserta']);
    // peserta cek
    Route::get('peserta_nomorkartu', [VclaimBPJSController::class, 'peserta_nomorkartu'])->name('api.cek_nomorkartu');
    Route::get('peserta_nik', [VclaimBPJSController::class, 'peserta_nik'])->name('api.cek_nik');
    // rujukan
    Route::get('rujukan_nomor', [VclaimBPJSController::class, 'rujukan_nomor'])->name('api.rujukan_nomor');
    Route::get('rujukan_peserta', [VclaimBPJSController::class, 'rujukan_peserta'])->name('api.rujukan_peserta');
    Route::get('rujukan_rs_nomor', [VclaimBPJSController::class, 'rujukan_rs_nomor'])->name('api.rujukan_rs_nomor');
    Route::get('rujukan_rs_peserta', [VclaimBPJSController::class, 'rujukan_rs_peserta'])->name('api.rujukan_rs_peserta');
    Route::get('rujukan_jumlah_sep', [VclaimBPJSController::class, 'rujukan_jumlah_sep'])->name('api.rujukan_jumlah_sep');
    // sep
    Route::post('insert_sep', [VclaimBPJSController::class, 'insert_sep']);
    Route::delete('delete_sep', [VclaimBPJSController::class, 'delete_sep']);
    Route::get('cari_sep', [VclaimBPJSController::class, 'cari_sep']);
    Route::get('sep_internal', [VclaimBPJSController::class, 'sep_internal']);
    Route::delete('sep_internal_delete', [VclaimBPJSController::class, 'sep_internal_delete'])->name('api.sep_internal_delete');
    // surat kontrol
    Route::post('insert_rencana_kontrol', [VclaimBPJSController::class, 'insert_rencana_kontrol']);
    Route::post('surat_kontrol_insert', [VclaimBPJSController::class, 'surat_kontrol_insert'])->name('api.surat_kontrol_insert');
    Route::post('surat_kontrol_update', [VclaimBPJSController::class, 'surat_kontrol_update'])->name('api.surat_kontrol_update');
    Route::post('surat_kontrol_delete', [VclaimBPJSController::class, 'surat_kontrol_delete'])->name('api.surat_kontrol_delete');
    Route::get('surat_kontrol_nomor', [VclaimBPJSController::class, 'surat_kontrol_nomor'])->name('api.surat_kontrol_nomor');
    Route::get('surat_kontrol_peserta', [VclaimBPJSController::class, 'surat_kontrol_peserta'])->name('api.surat_kontrol_peserta');
    Route::get('surat_kontrol_poli', [VclaimBPJSController::class, 'surat_kontrol_poli'])->name('api.surat_kontrol_poli');
    Route::get('surat_kontrol_dokter', [VclaimBPJSController::class, 'surat_kontrol_dokter'])->name('api.surat_kontrol_dokter');
});

Route::prefix('wa')->group(function () {
    Route::post('callback', [WhatsappController::class, 'callback']);
    Route::get('index', [WhatsappController::class, 'index']);
    Route::post('send_message', [WhatsappController::class, 'send_message']);
    Route::post('daftar_antrian', [WhatsappController::class, 'daftar_antrian']);
});
