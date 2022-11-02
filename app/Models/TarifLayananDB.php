<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TarifLayananDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_tarif_header';
    // protected $primaryKey = 'KODE_TARIF_HEADER';
    public $timestamps = false;

    public function tarifdeails()
    {
        return $this->hasMany(TarifLayananDetailDB::class, 'KODE_TARIF_HEADER', 'KODE_TARIF_HEADER');
    }
}
