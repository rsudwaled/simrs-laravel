<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class JadwalPoliDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'mw_jadwal_poli';
    protected $primaryKey = 'id';
    protected $fillable = [
        'id',
        'kode_unit',
        'kode_paramedis',
        'hari',
        'jam_mulai',
        'jam_selesai',
        'status',
        'admin_id',
    ];
    public function unit()
    {
        return $this->belongsTo(UnitDB::class, 'kode_unit', 'kode_unit');
    }
    public function dokter()
    {
        return $this->belongsTo(ParamedisDB::class, 'kode_paramedis', 'kode_paramedis');
    }
}
