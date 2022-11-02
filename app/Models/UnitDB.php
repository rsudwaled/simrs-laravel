<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class UnitDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_unit';
    protected $primaryKey = 'kode_unit';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'kode_unit',
        'nama_unit',
        'nama_panggil',
        'kuota_total',
        'kuota_online',
    ];
    public function jadwals()
    {
        return $this->hasMany(JadwalPoliDB::class, 'kode_unit', 'kode_unit');
    }
    public function antrians()
    {
        return $this->hasMany(Antrian::class, 'kodepoli', 'KDPOLI');
    }
    public function lokasi()
    {
        return $this->hasOne(LokasiUnitDB::class, 'kode_unit', 'kode_unit');
    }
    public function poliklinik()
    {
        return $this->hasOne(PoliklinikDB::class, 'kodesubspesialis', 'KDPOLI');
    }
}
