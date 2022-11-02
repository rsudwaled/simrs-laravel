<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class JadwalOperasi extends Model
{
    use HasFactory;
    protected $fillable = [
        'kodebooking',
        'tanggaloperasi',
        'kodetindakan',
        'jenistindakan',
        'kodepoli',
        'namapoli',
        'kodedokter',
        'namadokter',
        'terlaksana',
        'nopeserta',
        'nik',
        'norm',
        'namapeserta',
    ];
}
