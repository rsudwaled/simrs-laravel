<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TarifLayananDetailDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_tarif_detail';
    // protected $primaryKey = 'KODE_TARIF_HEADER';
    public $timestamps = false;
}
