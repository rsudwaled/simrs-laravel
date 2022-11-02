<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Kecamatan extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_kecamatan';
    protected $primaryKey = 'kode_kecamatan';
    public $incrementing = false;
    protected $keyType = 'string';
}
