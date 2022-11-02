<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PoliklinikDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'jkn_poli';

    protected $fillable = [
        'kodepoli',
        'namapoli',
        'kodesubspesialis',
        'namasubspesialis',
        'subspesialis',
        'status',
        'lokasi',
        'lantaipendaftaran',
    ];

    public function antrians()
    {
        return $this->hasMany(Antrian::class,  'kodepoli', 'kodesubspesialis');
    }
    public function jadwals()
    {
        return $this->hasMany(JadwalDokter::class,  'kodepoli', 'kodepoli');
    }
}
