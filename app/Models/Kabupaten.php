<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Kabupaten extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_kabupaten_kota';
    protected $primaryKey = 'kode_kabupaten_kota';
    public $incrementing = false;
    protected $keyType = 'string';
}
