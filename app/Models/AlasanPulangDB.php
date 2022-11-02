<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class AlasanPulangDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'mt_alasan_pulang';
    protected $primaryKey = 'kode';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [];
}
