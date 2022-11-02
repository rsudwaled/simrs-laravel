<?php

use App\Http\Controllers\AntrianController;
use App\Http\Controllers\DokterController;
use App\Http\Controllers\FileRMController;
use App\Http\Controllers\Icd10Controller;
use App\Http\Controllers\JadwalDokterController;
use App\Http\Controllers\JadwalLiburController;
use App\Http\Controllers\JadwalOperasiController;
use App\Http\Controllers\KPOController;
use App\Http\Controllers\KunjunganController;
use App\Http\Controllers\PasienController;
use App\Http\Controllers\PermissionController;
use App\Http\Controllers\PoliklinikController;
use App\Http\Controllers\RekamMedis\IndexController;
use App\Http\Controllers\RoleController;
use App\Http\Controllers\TarifKelompokLayananController;
use App\Http\Controllers\TarifLayananController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\VclaimController;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
Route::get('daftar_pasien', function () {
    return view('simrs.daftar_pasien');
})->name('daftar_pasien');
Auth::routes();
Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');
Route::get('/status', [App\Http\Controllers\HomeController::class, 'status'])->name('status');
Route::get("log-message", function () {
    $message = "This is a sample message for Test.";
    Log::emergency($message);
    Log::alert($message);
    Log::critical($message);
    Log::error($message);
    Log::warning($message);
    Log::notice($message);
    Log::info($message);
    Log::debug($message);
});

Route::get('daftar_pasien', [AntrianController::class, 'daftar_pasien'])->name('daftar_pasien');
Route::get('info_jadwaldokter', [JadwalDokterController::class, 'index'])->name('info_jadwaldokter');
Route::get('info_jadwallibur', [JadwalLiburController::class, 'index'])->name('info_jadwallibur');
Route::get('info_jadwaloperasi', [JadwalOperasiController::class, 'index'])->name('info_jadwaloperasi');
// antrian routes
Route::prefix('antrian')->name('antrian.')->group(function () {
    Route::get('console', [AntrianController::class, 'console'])->name('console');
    Route::get('cek_post', [AntrianController::class, 'cek_post'])->name('cek_post');
    Route::post('store_offline', [AntrianController::class, 'store_offline'])->name('store_offline');
    Route::get('console_jadwaldokter/{poli}/{tanggal}', [AntrianController::class, 'console_jadwaldokter'])->name('console_jadwaldokter');
    Route::get('tambah_offline/{poli}/{dokter}/{jam}', [AntrianController::class, 'tambah_offline'])->name('tambah_offline');
    Route::get('checkin_update', [AntrianController::class, 'checkin_update'])->name('checkin_update');
});
Route::prefix('antrian')->name('antrian.')->middleware(['auth'])->group(function () {
    // console
    Route::get('laporan', [AntrianController::class, 'laporan'])->name('laporan');
    Route::get('laporan_tanggal', [AntrianController::class, 'laporan_tanggal'])->name('laporan_tanggal');
    Route::get('laporan_bulan', [AntrianController::class, 'laporan_bulan'])->name('laporan_bulan');
    Route::get('taskid', [AntrianController::class, 'taskid'])->name('taskid');
    Route::get('{kodebookig}/edit', [AntrianController::class, 'edit'])->name('edit');
    // pendafataran
    Route::get('pendaftaran', [AntrianController::class, 'pendaftaran'])->name('pendaftaran')->middleware('permission:pendaftaran');
    Route::get('panggil_pendaftaran/{kodebooking}/{loket}/{lantai}', [AntrianController::class, 'panggil_pendaftaran'])->name('panggil_pendaftaran')->middleware('permission:pendaftaran');
    Route::post('update_pendaftaran_offline', [AntrianController::class, 'update_pendaftaran_offline'])->name('update_pendaftaran_offline')->middleware('permission:pendaftaran');
    Route::post('update_pendaftaran_online', [AntrianController::class, 'update_pendaftaran_online'])->name('update_pendaftaran_online')->middleware('permission:pendaftaran');
    Route::get('batal_antrian/{kodebooking}', [AntrianController::class, 'batal_antrian'])->name('batal_antrian')->middleware('permission:pendaftaran');
    // pembayaran
    Route::get('pembayaran', [AntrianController::class, 'pembayaran'])->name('pembayaran')->middleware('permission:kasir');
    Route::post('update_pembayaran', [AntrianController::class, 'update_pembayaran'])->name('update_pembayaran')->middleware('permission:kasir');
    // poliklinik
    Route::get('poli', [AntrianController::class, 'poli'])->name('poli')->middleware('permission:poliklinik');
    Route::get('panggil_poli/{kodebooking}', [AntrianController::class, 'panggil_poli'])->name('panggil_poli')->middleware('permission:poliklinik');
    Route::get('lanjut_farmasi/{kodebooking}', [AntrianController::class, 'lanjut_farmasi'])->name('lanjut_farmasi')->middleware('permission:poliklinik');
    Route::get('selesai/{kodebooking}', [AntrianController::class, 'selesai'])->name('selesai')->middleware('permission:poliklinik');
    Route::get('selesai_semua/{kodepoli}', [AntrianController::class, 'selesai_semua'])->name('selesai_semua')->middleware('permission:poliklinik');
    Route::get('surat_kontrol_poli', [AntrianController::class, 'surat_kontrol_poli'])->name('surat_kontrol_poli')->middleware('permission:poliklinik');
    Route::post('surat_kontrol_create', [AntrianController::class, 'surat_kontrol_create'])->name('surat_kontrol_create')->middleware('permission:poliklinik');
    Route::get('laporan_kunjungan_poliklinik', [AntrianController::class, 'laporan_kunjungan_poliklinik'])->name('laporan_kunjungan_poliklinik')->middleware('permission:poliklinik');
    // farmasi
    Route::get('farmasi', [AntrianController::class, 'farmasi'])->name('farmasi')->middleware('permission:farmasi');
    Route::get('panggil_farmasi/{kodebooking}', [AntrianController::class, 'panggil_farmasi'])->name('panggil_farmasi')->middleware('permission:farmasi');
    Route::get('racik_farmasi/{kodebooking}', [AntrianController::class, 'racik_farmasi'])->name('racik_farmasi')->middleware('permission:farmasi');
    Route::get('selesai_farmasi/{kodebooking}', [AntrianController::class, 'selesai_farmasi'])->name('selesai_farmasi')->middleware('permission:farmasi');
    Route::get('{kodebookig}/show', [AntrianController::class, 'show'])->name('show');
    Route::get('display_pendaftaran', [AntrianController::class, 'display_pendaftaran'])->name('display_pendaftaran');
    Route::get('/', [AntrianController::class, 'index'])->name('index');
    Route::get('cari_pasien/{nik}', [AntrianController::class, 'cari_pasien'])->name('cari_pasien');
    Route::prefix('ref')->name('ref.')->group(function () {
        Route::get('poli', [AntrianController::class, 'ref_poli'])->name('poli');
        Route::get('get_poli_bpjs', [AntrianController::class, 'get_poli_bpjs'])->name('get_poli_bpjs');
        Route::get('dokter', [AntrianController::class, 'ref_dokter'])->name('dokter');
        Route::get('get_dokter_bpjs', [AntrianController::class, 'get_dokter_bpjs'])->name('get_dokter_bpjs');
        Route::get('jadwaldokter', [AntrianController::class, 'ref_jadwaldokter'])->name('jadwaldokter');
        Route::get('get_jadwal_bpjs', [AntrianController::class, 'get_jadwal_bpjs'])->name('get_jadwal_bpjs');
    });
    Route::post('store', [AntrianController::class, 'store'])->name('store');
    Route::get('baru_online/{kodebooking}', [AntrianController::class, 'baru_online'])->name('baru_online');
    Route::post('simpan_baru_online/{kodebooking}', [AntrianController::class, 'simpan_baru_online'])->name('simpan_baru_online');
    Route::get('baru_offline/{kodebooking}', [AntrianController::class, 'baru_offline'])->name('baru_offline');
});
// admin user role permission
Route::prefix('admin')->name('admin.')->middleware(['auth', 'verified', 'permission:admin'])->group(function () {
    Route::resource('user', UserController::class);
    Route::resource('role', RoleController::class);
    Route::resource('permission', PermissionController::class);
});
Route::get('profile', [UserController::class, 'profile'])->name('profile');

// vcalim
Route::prefix('vclaim')->name('vclaim.')->middleware(['auth'])->group(function () {
    Route::get('/', [VclaimController::class, 'index'])->name('index');
    Route::get('monitoring_pelayanan_peserta', [VclaimController::class, 'monitoring_pelayanan_peserta'])->name('monitoring_pelayanan_peserta');
    Route::get('data_surat_kontrol', [VclaimController::class, 'data_surat_kontrol'])->name('data_surat_kontrol');
    Route::get('edit_surat_kontrol/{id}', [VclaimController::class, 'edit_surat_kontrol'])->name('edit_surat_kontrol');
    Route::get('sep_internal', [VclaimController::class, 'sep_internal'])->name('sep_internal');
    Route::post('buat_surat_kontrol', [VclaimController::class, 'buat_surat_kontrol'])->name('buat_surat_kontrol');
    Route::post('update_surat_kontrol', [VclaimController::class, 'update_surat_kontrol'])->name('update_surat_kontrol');
    Route::delete('sep_internal_delete', [VclaimController::class, 'sep_internal_delete'])->name('sep_internal_delete');
    Route::delete('delete_sep/{noSep}', [VclaimController::class, 'delete_sep'])->name('delete_sep');
    Route::delete('delete_surat_kontrol/{noSuratKontrol}', [VclaimController::class, 'delete_surat_kontrol'])->name('delete_surat_kontrol');
});

Route::resource('poli', PoliklinikController::class)->only(['index', 'create', 'edit', 'show', 'store'])->middleware('permission:pelayanan-medis');
Route::resource('dokter', DokterController::class)->only(['index', 'create'])->middleware('permission:pelayanan-medis');
Route::resource('jadwaldokter', JadwalDokterController::class)->only(['index', 'store', 'edit'])->middleware('permission:pelayanan-medis');
Route::resource('jadwallibur', JadwalLiburController::class)->middleware(['auth', 'permission:pelayanan-medis']);
Route::resource('jadwaloperasi', JadwalOperasiController::class)->only(['index', 'store', 'edit'])->middleware('permission:pelayanan-medis');
Route::resource('kunjungan', KunjunganController::class)->middleware('permission:rekam-medis');
Route::resource('pasien', PasienController::class)->middleware('permission:rekam-medis');
Route::get('pasien_daerah', [PasienController::class, 'pasien_daerah'])->name('pasien_daerah');
Route::get('pasien_demografi', [PasienController::class, 'pasien_demografi'])->name('pasien_demografi');
Route::get('index_penyakit_rajal', [IndexController::class, 'index_penyakit_rajal'])->name('index_penyakit_rajal');

Route::resource('tindakan', PasienController::class)->middleware('permission:rekam-medis');
Route::resource('tarif_kelompok_layanan', TarifKelompokLayananController::class);
Route::resource('tarif_layanan', TarifLayananController::class);
Route::resource('icd10', Icd10Controller::class);
Route::resource('efilerm', FileRMController::class);
Route::resource('kpo', KPOController::class);
