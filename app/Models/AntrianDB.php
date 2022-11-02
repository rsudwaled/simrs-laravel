<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AntrianDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'mw_antrian';
    protected $primaryKey = 'id';

    protected $fillable = [
        'kode_antrian',
        'tanggal',
        'nik',
        'nama_antrian',
        'nama',
        'no_rm',
        'phone',
        'kode_poli',
        'tipe',
        'status',
        'nomor_bpjs',
        'no_urut',
    ];

    public function unit()
    {
        return $this->belongsTo(UnitDB::class, 'kode_poli', 'kode_unit');
    }
}
