<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class JadwalDokter extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'jkn_jadwal_dokter';

    protected $fillable = [
        'kodepoli',
        'namapoli',
        'kodesubspesialis',
        'namasubspesialis',
        'namadokter',
        'kodedokter',
        'hari',
        'namahari',
        'jadwal',
        'libur',
        'kapasitaspasien',
    ];
}
