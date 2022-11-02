<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Dokter extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'jkn_dokter';

    protected $fillable = [
        'namadokter',
        'kodedokter',
        'nohp',
        'status',
    ];
}
