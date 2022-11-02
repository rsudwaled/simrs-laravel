<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PasienDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_pasien';
    protected $primaryKey = 'no_rm';
    public $timestamps = false;
    const CREATED_AT = 'tgl_entry';
    // const UPDATED_AT = 'last_update';

    protected $fillable = [
        "no_Bpjs",
        "nik_bpjs",
        "no_rm",
        "nama_px",
        "jenis_kelamin",
        "tgl_lahir",
        "no_tlp",
        "no_hp",
        "alamat",
        "kode_propinsi",
        "kode_kabupaten",
        "kode_kecamatan",
        "kode_desa",
    ];
    public function kecamatans()
    {
        return $this->hasOne(Kecamatan::class, 'kode_kecamatan', 'kecamatan');
    }
}
