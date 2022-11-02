<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class FileRekamMedis extends Model
{
    use HasFactory;

    protected $fillable = [
        'norm',
        'nama',
        'nomorkartu',
        'nik',
        'nohp',
        'tanggallahir',
        'jenisberkas',
        'namafile',
        'tanggalscan',
        'fileurl',
    ];
}
