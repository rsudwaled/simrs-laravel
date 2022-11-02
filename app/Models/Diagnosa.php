<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Diagnosa extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'di_pasien_diagnosa';
    protected $primaryKey = 'kode_kunjungan';
    public $incrementing = false;
    protected $keyType = 'string';

    public function pasien()
    {
        return $this->belongsTo(PasienDB::class, 'no_rm', 'no_rm');
    }
    public function kunjungan()
    {
        return $this->belongsTo(KunjunganDB::class, 'kode_kunjungan', 'kode_kunjungan');
    }
    public function dokter()
    {
        return $this->belongsTo(ParamedisDB::class, 'kode_paramedis', 'kode_paramedis');
    }
}
