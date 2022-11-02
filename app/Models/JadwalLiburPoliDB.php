<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class JadwalLiburPoliDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'jkn_jadwal_libur';
    protected $primaryKey = 'id';

    protected $fillable = [
        'tanggal_awal',
        'tanggal_akhir',
        'kode_poli',
        'keterangan',
        'status',
    ];

    public function unit()
    {
        return $this->belongsTo(UnitDB::class, 'kode_poli', 'kode_unit');
    }
    public function antrians()
    {
        return $this->hasMany(Antrian::class,  'tanggal', 'tanggalperiksa');
    }
}
