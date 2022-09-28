<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SepDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'jkn_sep';
    protected $fillable = [
        'noSep',
        'tglSep',
        'jnsPelayanan',
        'kelasRawat',
        'diagnosa',
        'noRujukan',
        'poli',
        'poliEksekutif',
        'catatan',
        'penjamin',
        // peserta
        'noKartu',
        'nama',
        'tglLahir',
        'noMr',
        'kelamin',
        'jnsPeserta',
        'hakKelas',
        'noTelp',
        'asuransi',
        // informasi
        'dinsos',
        'prolanisPRB',
        'noSKTM',
    ];
}
