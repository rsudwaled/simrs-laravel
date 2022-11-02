<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ParamedisDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_paramedis';
    protected $fillable = [

    ];
}
