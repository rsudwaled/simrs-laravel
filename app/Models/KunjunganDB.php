<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KunjunganDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'ts_kunjungan';
    protected $primaryKey = 'kode_kunjungan';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'counter',
        'no_rm',
        'kode_unit',
        'tgl_masuk',
        'kode_paramedis',
        'status_kunjungan',
        'prefix_kunjungan',
        'kode_penjamin',
        'pic',
        'id_alasan_masuk',
        'pic2',
        'kelas',
        'hak_kelas',
        'no_sep',
        'no_rujukan',
        'diagx',
        'created_at',
        'keterangan2',
    ];
    public function pasien()
    {
        return $this->belongsTo(PasienDB::class, 'no_rm', 'no_rm');
    }
    public function unit()
    {
        return $this->belongsTo(UnitDB::class, 'kode_unit', 'kode_unit');
    }
    public function status()
    {
        return $this->belongsTo(StatusKunjunganDB::class,   'status_kunjungan', 'ID',);
    }
    public function penjamin()
    {
        return $this->hasOne(PenjaminDB::class, 'kode_penjamin_simrs', 'kode_penjamin');
    }
    public function penjamin_simrs()
    {
        return $this->hasOne(PenjaminSimrs::class, 'kode_penjamin', 'kode_penjamin');
    }
    public function diagnosapoli()
    {
        return $this->hasOne(DiagnosaPoli::class, 'kode_kunjungan', 'kode_kunjungan');
    }
    // public function layanans()
    // {
    //     return $this->hasMany(LayananHeaderDB::class, 'kode_kunjungan', 'kode_kunjungan');
    // }
    public function dokter()
    {
        return $this->belongsTo(ParamedisDB::class, 'kode_paramedis', 'kode_paramedis');
    }
    public function surat_kontrol()
    {
        return $this->hasOne(SuratKontrol::class, 'noSepAsalKontrol', 'no_sep');
    }
}
