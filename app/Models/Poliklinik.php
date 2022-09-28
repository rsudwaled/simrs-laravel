<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Poliklinik extends Model
{
    use HasFactory;

    protected $fillable = [
        'kodepoli',
        'namapoli',
        'kodesubspesialis',
        'namasubspesialis',
        'subspesialis',
        'lokasi',
        'loket',
        'status',
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
