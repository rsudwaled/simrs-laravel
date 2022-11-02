<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TarifKelompokLayananDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_tarif_kelompok';
    protected $primaryKey = 'kelompok_tarif_id';
    public $timestamps = false;
}
